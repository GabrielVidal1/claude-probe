// Package paths says where claude-probe keeps its socket, store and logs.
package paths

import (
	"os"
	"path/filepath"
	"runtime"
)

const name = "claude-probe"

func home() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return "/tmp"
}

// StateDir holds the store, the daemon's lock and its log.
func StateDir() string {
	if d := os.Getenv("CLAUDE_PROBE_STATE_DIR"); d != "" {
		return d
	}
	// Not $XDG_STATE_HOME / $XDG_RUNTIME_DIR: a hook runs in whatever
	// environment its session has (a service's, a scrubbed one), and every
	// hook and reader of one user must agree on one daemon and one store.
	if runtime.GOOS == "darwin" {
		return filepath.Join(home(), "Library", "Application Support", name)
	}
	return filepath.Join(home(), ".local", "state", name)
}

// Socket is where the daemon listens (hooks, the API). A unix socket path
// must stay under ~100 bytes, so it lives in a short directory.
func Socket() string {
	if s := os.Getenv("CLAUDE_PROBE_SOCK"); s != "" {
		return s
	}
	if runtime.GOOS == "darwin" {
		return filepath.Join(home(), "Library", "Caches", name, "probe.sock")
	}
	return filepath.Join(home(), ".cache", name, "probe.sock")
}

func DB() string   { return filepath.Join(StateDir(), "probe.db") }
func Lock() string { return filepath.Join(StateDir(), "daemon.lock") }
func Log() string  { return filepath.Join(StateDir(), "daemon.log") }

// Ensure makes the private directories (0700) the paths live in.
func Ensure() error {
	if err := os.MkdirAll(StateDir(), 0o700); err != nil {
		return err
	}
	return os.MkdirAll(filepath.Dir(Socket()), 0o700)
}
