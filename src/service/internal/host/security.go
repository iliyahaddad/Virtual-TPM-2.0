// Package host provides HTTP API security for the vTPM2 service.
// The API listens on 127.0.0.1:8082 (loopback only). Access is controlled by
// an access token stored in the state directory with restrictive Windows ACLs.
// State-changing operations additionally require a CSRF token.
package host

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// authTokenFile is the filename for the API access token within the state dir.
const authTokenFile = "auth.token"

// tokenHeader is the HTTP header used to present the access token.
const tokenHeader = "Authorization"

// csrfHeader is the HTTP header used to present the CSRF token.
const csrfHeader = "X-VTPM2-CSRF"

// maxRequestBody is the maximum request body size (1 MiB).
const maxRequestBody = 1 << 20

// authToken is the current API access token. Empty means authentication is
// not required (development mode only).
var authToken string

// loadOrCreateAuthToken loads the access token from the state directory, or
// creates a new one if none exists. The token file is created with restrictive
// permissions.
func loadOrCreateAuthToken(dir string) (string, error) {
	tokenPath := filepath.Join(dir, authTokenFile)
	data, err := os.ReadFile(tokenPath)
	if err == nil {
		return strings.TrimSpace(string(data)), nil
	}
	if !os.IsNotExist(err) {
		return "", fmt.Errorf("read auth token: %w", err)
	}

	// Generate a new 256-bit token.
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate auth token: %w", err)
	}
	token := hex.EncodeToString(buf)

	if err := os.WriteFile(tokenPath, []byte(token), 0o600); err != nil {
		return "", fmt.Errorf("write auth token: %w", err)
	}
	if err := ensureStateFileSecurity(tokenPath); err != nil {
		// ACL failure is non-fatal; the token file still has 0o600 perms.
		fmt.Fprintf(os.Stderr, "vtpm2: warning: set auth token ACL: %v\n", err)
	}
	return token, nil
}

// requireAuth returns middleware that requires a valid bearer token.
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authToken == "" {
			next(w, r)
			return
		}
		hdr := r.Header.Get(tokenHeader)
		if !strings.HasPrefix(hdr, "Bearer ") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(hdr, "Bearer ")
		if token != authToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// requireCSRF returns middleware that requires a CSRF token for
// state-changing operations.
func requireCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next(w, r)
			return
		}
		csrf := r.Header.Get(csrfHeader)
		if csrf == "" || csrf != authToken {
			http.Error(w, "missing or invalid CSRF token", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// securityHeaders adds standard security headers to all responses.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// corsMiddleware restricts CORS to loopback origins only.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "http://127.0.0.1:8082" || origin == "http://localhost:8082" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-VTPM2-CSRF")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// hostValidation ensures only loopback hosts are served.
func hostValidation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if host != "127.0.0.1:8082" && host != "localhost:8082" && host != "[::1]:8082" {
			http.Error(w, "invalid host", http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// bodySizeLimit limits the request body size.
func bodySizeLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs each request using the provided log function.
func loggingMiddleware(logf func(format string, args ...interface{}), next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		logf("HTTP %s %s from %s in %v", r.Method, r.URL.Path, r.RemoteAddr, time.Since(start))
	})
}

// writeAuthToken stores the auth token for use by middleware.
func (h *Host) setAuthToken(token string) {
	authToken = token
}

// applySecurity wraps the mux with security middleware.
func (h *Host) applySecurity(mux http.Handler) http.Handler {
	return loggingMiddleware(h.logf,
		securityHeaders(
			corsMiddleware(
				hostValidation(
					bodySizeLimit(mux),
				),
			),
		),
	)
}
