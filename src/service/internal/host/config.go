package host

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// Config is the vTPM2 service configuration.
type Config struct {
	StateDir     string `json:"stateDir"`
	HTTPPort     int    `json:"httpPort"`
	HTTPBind     string `json:"httpBind"`
	LogRetention int    `json:"logRetention"`
	StartupType  string `json:"startupType"`
	SecureDelete bool   `json:"secureDelete"`
	EncryptAtRest bool  `json:"encryptAtRest"`
}

// defaultConfig returns the built-in default configuration.
func defaultConfig() Config {
	return Config{
		StateDir:     "",
		HTTPPort:     8082,
		HTTPBind:     "127.0.0.1",
		LogRetention: 500,
		StartupType:  "CLEAR",
		SecureDelete: false,
	}
}

// LoadConfig reads config.json from the same directory as the executable, or
// from the path in the VTPM2_CONFIG environment variable. Missing or unreadable
// files fall back to defaults.
func LoadConfig() Config {
	cfg := defaultConfig()
	path := os.Getenv("VTPM2_CONFIG")
	if path == "" {
		exe, err := os.Executable()
		if err == nil {
			path = filepath.Join(filepath.Dir(exe), "config.json")
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg
	}
	// Expand %PROGRAMDATA% and other %VAR% references in StateDir.
	cfg.StateDir = expandEnv(cfg.StateDir)
	return cfg
}

// expandEnv replaces %VAR% references with their environment values.
func expandEnv(s string) string {
	for {
		start := strings.IndexByte(s, '%')
		if start < 0 {
			return s
		}
		end := strings.IndexByte(s[start+1:], '%')
		if end < 0 {
			return s
		}
		end += start + 1
		name := s[start+1 : end]
		val := os.Getenv(name)
		s = s[:start] + val + s[end+1:]
	}
}
