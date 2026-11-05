package setup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHooksAddedOnceKeptInOrderUpdatedAndRemoved(t *testing.T) {
	t.Setenv("CLAUDE_PROBE_STATE_DIR", t.TempDir())
	p := filepath.Join(t.TempDir(), "settings.json")
	orig := `{"model": "opus", "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "rtk hook claude"}]}]}, "theme": "dark"}`
	if err := os.WriteFile(p, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err := Apply(p, Options{Bin: "/opt/claude-probe"})
	if err != nil || !changed {
		t.Fatal(changed, err)
	}
	raw, _ := os.ReadFile(p)
	s := string(raw)
	if strings.Index(s, `"model"`) > strings.Index(s, `"hooks"`) || strings.Index(s, `"hooks"`) > strings.Index(s, `"theme"`) {
		t.Fatal("key order changed:", s)
	}
	var doc struct {
		Hooks map[string][]struct {
			Matcher string `json:"matcher"`
			Hooks   []struct {
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Hooks) != 6 || len(doc.Hooks["PreToolUse"]) != 2 ||
		doc.Hooks["PreToolUse"][0].Hooks[0].Command != "rtk hook claude" ||
		doc.Hooks["Stop"][0].Matcher != "" || doc.Hooks["PostToolUse"][0].Matcher != ToolMatcher {
		t.Fatal(doc.Hooks)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatal(st.Mode())
	}
	if changed, _ := Apply(p, Options{Bin: "/opt/claude-probe"}); changed {
		t.Fatal("second install changed the file")
	}
	if changed, _ := Apply(p, Options{Bin: "/usr/local/bin/claude-probe"}); !changed {
		t.Fatal("a moved binary must rewrite the command")
	}
	raw, _ = os.ReadFile(p)
	if strings.Count(string(raw), Marker) != 6 || !strings.Contains(string(raw), "/usr/local/bin/claude-probe hook") {
		t.Fatal(string(raw))
	}
	if changed, _ := Apply(p, Options{Remove: true}); !changed {
		t.Fatal("uninstall did nothing")
	}
	raw, _ = os.ReadFile(p)
	if strings.Contains(string(raw), Marker) || !strings.Contains(string(raw), "rtk hook claude") ||
		strings.Contains(string(raw), "Stop") {
		t.Fatal(string(raw))
	}
}

func TestStatuslineWrapsTheUsersOwnAndRestoresIt(t *testing.T) {
	t.Setenv("CLAUDE_PROBE_STATE_DIR", t.TempDir())
	p := filepath.Join(t.TempDir(), "settings.json")
	_ = os.WriteFile(p, []byte(`{"statusLine": {"type": "command", "command": "bash ~/my line.sh", "padding": 1}}`), 0o600)
	if _, err := Apply(p, Options{Bin: "/opt/cp", Statusline: true}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	var doc map[string]map[string]any
	_ = json.Unmarshal(raw, &doc)
	cmd := doc["statusLine"]["command"].(string)
	if !strings.HasPrefix(cmd, "/opt/cp statusline --wrap 'bash ~/my line.sh'") || doc["statusLine"]["padding"] != 1.0 {
		t.Fatal(cmd, doc)
	}
	if changed, _ := Apply(p, Options{Bin: "/opt/cp", Statusline: true}); changed {
		t.Fatal("second install changed the status line")
	}
	if _, err := Apply(p, Options{Remove: true}); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(p)
	_ = json.Unmarshal(raw, &doc)
	if doc["statusLine"]["command"] != "bash ~/my line.sh" {
		t.Fatal(string(raw))
	}
}

func TestNotAnObjectIsRefused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	_ = os.WriteFile(p, []byte(`[1, 2]`), 0o600)
	if _, err := Apply(p, Options{Bin: "x"}); err == nil {
		t.Fatal("a JSON array was edited")
	}
}
