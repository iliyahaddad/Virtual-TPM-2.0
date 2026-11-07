package host

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// handleDashboard serves the built-in management UI.
func (h *Host) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(dashboardHTML))
}

// handleStatus returns service/engine status.
func (h *Host) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, h.Status())
}

// handleCapability runs a genuine TPM2_GetCapability for TPM properties.
func (h *Host) handleCapability(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.mu.RLock()
	tpm := h.tpm
	h.mu.RUnlock()
	if tpm == nil {
		http.Error(w, "engine not initialized", http.StatusServiceUnavailable)
		return
	}
	// TPM2_GetCapability(capability=TPM_CAP_TPM_PROPERTIES, property=TPM_PT_FIXED, count=48)
	const (
		tpmSTNoSessions = 0x8001
		ccGetCapability = 0x0000017a
		tpmCapTPMProps  = 0x00000006
		tpmPTFixed      = 0x00000100
	)
	var params [12]byte
	binary.BigEndian.PutUint32(params[0:], tpmCapTPMProps)
	binary.BigEndian.PutUint32(params[4:], tpmPTFixed)
	binary.BigEndian.PutUint32(params[8:], 48)
	cmd := buildCmd(tpmSTNoSessions, ccGetCapability, params[:])
	resp := tpm.Execute(cmd)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"command": "TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES, TPM_PT_FIXED, 48)",
		"response": hex.EncodeToString(resp),
	})
}

// handlePCR returns PCR bank values.
func (h *Host) handlePCR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, h.PCR())
}

// handleNV returns NV index summary.
func (h *Host) handleNV(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, h.NV())
}

// handleCommand executes a raw TPM command. Body is raw hex or {"command":"hex"}.
func (h *Host) handleCommand(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	body = bytesTrimSpace(body)
	var cmdHex string
	if len(body) > 0 && body[0] == '{' {
		var m struct {
			Command string `json:"command"`
		}
		if err := json.Unmarshal(body, &m); err != nil || m.Command == "" {
			http.Error(w, `expected {"command":"<hex>"}`, http.StatusBadRequest)
			return
		}
		cmdHex = m.Command
	} else {
		cmdHex = strings.TrimSpace(string(body))
	}
	cmd, err := hex.DecodeString(strings.ReplaceAll(cmdHex, " ", ""))
	if err != nil {
		http.Error(w, "invalid hex command", http.StatusBadRequest)
		return
	}
	resp, err := h.Execute(cmd)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	h.logf("command executed: %d bytes in, %d bytes out", len(cmd), len(resp))
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"response": hex.EncodeToString(resp),
	})
}

// handleStateBackup exports the full persistent state.
func (h *Host) handleStateBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	blob, err := h.StateBlob()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="vtpm2-state.json"`)
	_, _ = w.Write(blob)
}

// handleStateRestore replaces state from an uploaded JSON blob.
func (h *Host) handleStateRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	if err := h.RestoreBlob(body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.logf("state restored via API")
	writeJSON(w, http.StatusOK, map[string]string{"status": "restored"})
}

// handleLogs returns recent diagnostic lines.
func (h *Host) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"logs": h.Logs()})
}

func bytesTrimSpace(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}
