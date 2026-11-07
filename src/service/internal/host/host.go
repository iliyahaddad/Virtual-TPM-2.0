// Package host runs the vTPM2 software TPM 2.0 engine inside a Windows host
// process: engine initialization, persistent state, an HTTP command/diagnostic
// API, and the dashboard GUI. It has no external dependencies beyond the Go
// standard library and the vendored go-sdk-vtpm2 engine.

package host

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/deploymenttheory/go-sdk-vtpm2/state"
	"github.com/deploymenttheory/go-sdk-vtpm2/tpm2"
)

// logCap is the maximum number of in-memory diagnostic log lines retained.
var logCap = 500

// Host is the running vTPM2 instance.
type Host struct {
	mu   sync.RWMutex
	tpm  *tpm2.TPM
	store *state.Store
	dir  string
	cfg  Config

	server *http.Server
	started bool

	logs []string
}

// New creates a host bound to stateDir.
func New(stateDir string) *Host {
	return &Host{dir: stateDir, logs: []string{"vTPM2 host created"}}
}

// NewFromConfig creates a host from a configuration.
func NewFromConfig(cfg Config) *Host {
	h := New(cfg.StateDir)
	h.cfg = cfg
	if h.cfg.LogRetention > 0 {
		logCap = h.cfg.LogRetention
	}
	return h
}

// Status is a snapshot of host status for the dashboard.
type Status struct {
	Running      bool   `json:"running"`
	EngineStarted bool  `json:"engineStarted"`
	StateDir     string `json:"stateDir"`
	StateLoaded  bool   `json:"stateLoaded"`
	OS           string `json:"os"`
}

// logf appends a diagnostic line (retained in memory for the dashboard).
func (h *Host) logf(format string, args ...interface{}) {
	h.mu.Lock()
	line := fmt.Sprintf(format, args...)
	h.logs = append(h.logs, line)
	if len(h.logs) > logCap {
		h.logs = h.logs[len(h.logs)-logCap:]
	}
	h.mu.Unlock()
	log.Print(line)
}

// resolveStateDir picks a writable state directory with restrictive Windows ACLs.
func resolveStateDir() string {
	if d := os.Getenv("PROGRAMDATA"); d != "" {
		p := filepath.Join(d, "vTPM2")
		if err := ensureStateDirSecurity(p); err == nil {
			return p
		}
	}
	p := filepath.Join("vTPM2-state")
	if err := ensureStateDirSecurity(p); err != nil {
		_ = os.MkdirAll(p, 0o700)
	}
	return p
}

// Start initializes the TPM engine, restores persisted state, sends TPM2_Startup,
// and starts the HTTP API/dashboard on localhost:httpPort.
func (h *Host) Start() error {
	h.mu.Lock()
	if h.started {
		h.mu.Unlock()
		return fmt.Errorf("host already started")
	}
	h.started = true
	h.mu.Unlock()

	if h.dir == "" {
		h.dir = resolveStateDir()
	}
	h.logf("state directory: %s", h.dir)

	store, err := state.NewStore(h.dir)
	if h.cfg.EncryptAtRest {
		store, err = state.NewEncryptedStore(h.dir, dpapiEncrypt, dpapiDecrypt)
	}
	if err != nil {
		return fmt.Errorf("create state store: %w", err)
	}
	h.store = store
	// Apply restrictive Windows ACLs to the state directory.
	if err := ensureStateDirSecurity(h.dir); err != nil {
		return fmt.Errorf("set state dir ACL: %w", err)
	}

	h.tpm = tpm2.New()
	if loaded, err := store.LoadInto(h.tpm); err != nil {
		return fmt.Errorf("load state: %w", err)
	} else {
		h.logf("persisted state restored: %v", loaded)
	}

	// TPM2_Startup(TPM_SU_CLEAR) brings the engine from "powered on" to "started".
	if err := h.startupClear(); err != nil {
		return fmt.Errorf("TPM2_Startup: %w", err)
	}
	h.logf("TPM engine started")

	// Load or create the API access token. Stored in the state directory with
	// restrictive Windows ACLs.
	token, err := loadOrCreateAuthToken(h.dir)
	if err != nil {
		return fmt.Errorf("load auth token: %w", err)
	}
	h.setAuthToken(token)
	h.logf("API access token loaded")

	const httpPort = 8082
	mux := http.NewServeMux()

	// Public endpoints (no auth required).
	mux.HandleFunc("/", h.handleDashboard)
	mux.HandleFunc("/api/status", h.handleStatus)

	// Read-only endpoints require authentication.
	mux.HandleFunc("/api/capability", requireAuth(h.handleCapability))
	mux.HandleFunc("/api/pcr", requireAuth(h.handlePCR))
	mux.HandleFunc("/api/nv", requireAuth(h.handleNV))
	mux.HandleFunc("/api/logs", requireAuth(h.handleLogs))

	// Write endpoints require authentication + CSRF token.
	mux.HandleFunc("/api/command", requireCSRF(requireAuth(h.handleCommand)))
	mux.HandleFunc("/api/state/backup", requireAuth(h.handleStateBackup))
	mux.HandleFunc("/api/state/restore", requireCSRF(requireAuth(h.handleStateRestore)))

	h.server = &http.Server{
		Addr:              fmt.Sprintf("127.0.0.1:%d", httpPort),
		Handler:           h.applySecurity(mux),
		ReadHeaderTimeout: 0,
	}

	go func() {
		if err := h.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			h.logf("HTTP server error: %v", err)
		}
	}()
	h.logf("HTTP API listening on 127.0.0.1:%d", httpPort)
	return nil
}

// buildCmd frames a TPM command blob: header (tag, size, code) + params.
// All multi-byte fields are big-endian per the TPM 2.0 spec.
func buildCmd(tag uint16, code uint32, params []byte) []byte {
	out := make([]byte, 10+len(params))
	binary.BigEndian.PutUint16(out[0:], tag)
	binary.BigEndian.PutUint32(out[2:], uint32(len(out)))
	binary.BigEndian.PutUint32(out[6:], code)
	copy(out[10:], params)
	return out
}

// startupClear sends TPM2_Startup with TPM_SU_CLEAR.
func (h *Host) startupClear() error {
	const (
		tpmSTNoSessions = 0x8001
		ccStartup       = 0x00000144
		suClear         = 0x0000 // TPM_SU_CLEAR
	)
	var su [2]byte
	binary.BigEndian.PutUint16(su[:], suClear)
	resp := h.tpm.Execute(buildCmd(tpmSTNoSessions, ccStartup, su[:]))
	if len(resp) < 10 {
		return fmt.Errorf("short startup response (%d bytes)", len(resp))
	}
	rc := binary.BigEndian.Uint32(resp[6:])
	if rc != 0 {
		return fmt.Errorf("TPM2_Startup returned TPM_RC 0x%08x", rc)
	}
	return nil
}

// Stop shuts down the HTTP server and persists TPM state.
func (h *Host) Stop() error {
	h.mu.Lock()
	if h.server != nil {
		_ = h.server.Close()
	}
	h.mu.Unlock()

	h.mu.RLock()
	tpm := h.tpm
	store := h.store
	h.mu.RUnlock()

	if tpm != nil && store != nil {
		if err := store.Save(tpm.Snapshot()); err != nil {
			return fmt.Errorf("save state: %w", err)
		}
		// Apply restrictive Windows ACLs to the state file after writing.
		if err := ensureStateFileSecurity(store.Path()); err != nil {
			h.logf("warning: set state file ACL: %v", err)
		}
		h.logf("TPM state persisted")
	}
	return nil
}

// Execute forwards a raw TPM command blob to the engine and returns the response blob.
func (h *Host) Execute(cmd []byte) ([]byte, error) {
	h.mu.RLock()
	tpm := h.tpm
	started := h.started
	h.mu.RUnlock()
	if tpm == nil {
		return nil, fmt.Errorf("engine not initialized")
	}
	if !started {
		return nil, fmt.Errorf("engine not started")
	}
	resp := tpm.Execute(cmd)
	return resp, nil
}

// Status returns the current host status.
func (h *Host) Status() Status {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return Status{
		Running:       h.started,
		EngineStarted: h.started,
		StateDir:      h.dir,
		StateLoaded:   h.store != nil,
		OS:            runtime.GOOS + " " + runtime.GOARCH,
	}
}

// PCR returns PCR bank data for the dashboard.
func (h *Host) PCR() map[string]interface{} {
	h.mu.RLock()
	tpm := h.tpm
	h.mu.RUnlock()
	if tpm == nil {
		return nil
	}
	snap := tpm.Snapshot()
	out := map[string]interface{}{}
	for alg, bank := range snap.PCRBanks {
		entries := []map[string]interface{}{}
		for i, d := range bank {
			entries = append(entries, map[string]interface{}{"index": i, "digest": hex.EncodeToString(d)})
		}
		out[fmt.Sprintf("0x%04x", alg)] = entries
	}
	return out
}

// NV returns NV index summary for the dashboard.
func (h *Host) NV() []map[string]interface{} {
	h.mu.RLock()
	tpm := h.tpm
	h.mu.RUnlock()
	if tpm == nil {
		return nil
	}
	snap := tpm.Snapshot()
	out := []map[string]interface{}{}
	for _, idx := range snap.NVIndices {
		out = append(out, map[string]interface{}{
			"publicLen":   len(idx.Public),
			"dataLen":     len(idx.Data),
			"readLocked":  idx.ReadLocked,
			"writeLocked": idx.WriteLocked,
		})
	}
	return out
}

// Logs returns recent diagnostic lines.
func (h *Host) Logs() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]string, len(h.logs))
	copy(out, h.logs)
	return out
}

// StateBlob exports the full persistent state as a JSON blob.
func (h *Host) StateBlob() ([]byte, error) {
	h.mu.RLock()
	tpm := h.tpm
	h.mu.RUnlock()
	if tpm == nil {
		return nil, fmt.Errorf("engine not initialized")
	}
	return tpm.StateBlob()
}

// RestoreBlob replaces engine state from a previously exported JSON blob.
func (h *Host) RestoreBlob(blob []byte) error {
	h.mu.RLock()
	tpm := h.tpm
	h.mu.RUnlock()
	if tpm == nil {
		return fmt.Errorf("engine not initialized")
	}
	if err := tpm.LoadStateBlob(blob); err != nil {
		return err
	}
	h.logf("state restored from blob")
	return nil
}

// ensureJSON sets a JSON response.
func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// readAll reads the full request body.
func readAll(r io.Reader) ([]byte, error) {
	return io.ReadAll(r)
}

var _ = strings.TrimSpace
var _ = os.DevNull
