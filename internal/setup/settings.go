// Package setup puts claude-probe into Claude Code: its hooks (and, if
// asked, its status line segment) in a settings.json, found again by a
// marker so it is added once, updated when the binary moves, and removed
// cleanly — the user's own hooks and the file's key order left as they were.
package setup

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/GabrielVidal1/claude-probe/internal/paths"
)

const Marker = "# claude-probe"

// ToolMatcher: the tools the hook measures — Bash calls, and the file tools
// (what they change on disk, from a stat before and after).
const ToolMatcher = "Bash|Write|Edit|MultiEdit|NotebookEdit"

// The events the hook listens to; a matcher limits a tool event to those tools.
var Events = []struct{ Name, Matcher string }{
	{"PreToolUse", ToolMatcher}, {"PostToolUse", ToolMatcher}, {"UserPromptSubmit", ""},
	{"Stop", ""}, {"SubagentStart", ""}, {"SubagentStop", ""},
}

// object is a JSON object that keeps its keys' order.
type object struct {
	keys []string
	vals map[string]json.RawMessage
}

func parseObject(raw []byte) (*object, error) {
	o := &object{vals: map[string]json.RawMessage{}}
	if len(bytes.TrimSpace(raw)) == 0 {
		return o, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		k, _ := t.(string)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		if _, dup := o.vals[k]; !dup {
			o.keys = append(o.keys, k)
		}
		o.vals[k] = v
	}
	return o, nil
}

func (o *object) set(k string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = raw
	return nil
}

func (o *object) del(k string) {
	if _, ok := o.vals[k]; !ok {
		return
	}
	delete(o.vals, k)
	for i, x := range o.keys {
		if x == k {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			break
		}
	}
}

func (o *object) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kj, _ := json.Marshal(k)
		b.Write(kj)
		b.WriteByte(':')
		b.Write(o.vals[k])
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

func quote(s string) string {
	if !strings.ContainsAny(s, " '\"\\$`") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// HookCommand is the hook line for the binary at `bin`.
func HookCommand(bin string) string { return quote(bin) + " hook  " + Marker }

func ours(group map[string]any) bool {
	hs, _ := group["hooks"].([]any)
	for _, h := range hs {
		if m, ok := h.(map[string]any); ok && strings.Contains(fmt.Sprint(m["command"]), Marker) {
			return true
		}
	}
	return false
}

// Options of one Install / Uninstall.
type Options struct {
	Bin        string // absolute path the hooks run
	Statusline bool   // also put the status-line segment in
	Remove     bool
}

// Apply edits one settings.json; it reports whether the file changed.
func Apply(path string, opt Options) (bool, error) {
	if real, err := filepath.EvalSymlinks(path); err == nil {
		path = real // a guest's settings.json can be a link
	}
	raw, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	o, err := parseObject(raw)
	if err != nil {
		return false, fmt.Errorf("%s: %w", path, err)
	}
	hooks := map[string][]map[string]any{}
	var order []string
	if raw, ok := o.vals["hooks"]; ok {
		ho, err := parseObject(raw)
		if err != nil {
			return false, fmt.Errorf("%s: hooks: %w", path, err)
		}
		order = ho.keys
		for _, k := range ho.keys {
			var gs []map[string]any
			if err := json.Unmarshal(ho.vals[k], &gs); err != nil {
				return false, fmt.Errorf("%s: hooks.%s is not the CLI's shape", path, k)
			}
			hooks[k] = gs
		}
	}
	before, _ := json.Marshal(hooks)
	for _, e := range Events {
		var keep []map[string]any
		for _, g := range hooks[e.Name] {
			if !ours(g) {
				keep = append(keep, g)
			}
		}
		if !opt.Remove {
			g := map[string]any{"hooks": []any{map[string]any{"type": "command",
				"command": HookCommand(opt.Bin), "timeout": 5}}}
			if e.Matcher != "" {
				g["matcher"] = e.Matcher
			}
			keep = append(keep, g)
			if _, ok := hooks[e.Name]; !ok {
				order = append(order, e.Name)
			}
		}
		hooks[e.Name] = keep
	}
	after, _ := json.Marshal(hooks)
	changed := !bytes.Equal(before, after)
	ho := &object{vals: map[string]json.RawMessage{}}
	for _, k := range order {
		if len(hooks[k]) == 0 {
			continue
		}
		_ = ho.set(k, hooks[k])
	}
	if len(ho.keys) == 0 {
		o.del("hooks")
	} else if err := o.set("hooks", ho); err != nil {
		return false, err
	}
	if c, err := statusline(o, path, opt); err != nil {
		return false, err
	} else if c {
		changed = true
	}
	if !changed {
		return false, nil
	}
	return true, write(path, o)
}

// statusline wraps the user's status line (or sets one) so the segment
// shows; the original is kept next to the store to be restored.
func statusline(o *object, settings string, opt Options) (bool, error) {
	saved := filepath.Join(paths.StateDir(), "statusline-"+strings.ReplaceAll(strings.Trim(settings, "/"), "/", "_")+".json")
	var cur map[string]any
	if raw, ok := o.vals["statusLine"]; ok {
		_ = json.Unmarshal(raw, &cur)
	}
	mine := cur != nil && strings.Contains(fmt.Sprint(cur["command"]), Marker)
	if opt.Remove || !opt.Statusline {
		if !mine || !opt.Remove {
			return false, nil
		}
		if raw, err := os.ReadFile(saved); err == nil && len(bytes.TrimSpace(raw)) > 0 && string(bytes.TrimSpace(raw)) != "null" {
			o.vals["statusLine"] = json.RawMessage(bytes.TrimSpace(raw))
		} else {
			o.del("statusLine")
		}
		_ = os.Remove(saved)
		return true, nil
	}
	cmd := quote(opt.Bin) + " statusline"
	if mine {
		var orig map[string]any
		if raw, err := os.ReadFile(saved); err == nil {
			_ = json.Unmarshal(raw, &orig)
		}
		if orig != nil && orig["command"] != nil {
			cmd += " --wrap " + quote(fmt.Sprint(orig["command"]))
		}
	} else {
		if err := paths.Ensure(); err != nil {
			return false, err
		}
		raw, _ := json.Marshal(cur)
		if err := os.WriteFile(saved, raw, 0o600); err != nil {
			return false, err
		}
		if cur != nil && cur["command"] != nil {
			cmd += " --wrap " + quote(fmt.Sprint(cur["command"]))
		}
	}
	next := map[string]any{"type": "command", "command": cmd + "  " + Marker}
	if cur != nil && fmt.Sprint(cur["command"]) == next["command"] {
		return false, nil
	}
	if cur != nil && cur["padding"] != nil {
		next["padding"] = cur["padding"]
	}
	return true, o.set("statusLine", next)
}

func write(path string, o *object) error {
	raw, err := json.Marshal(o)
	if err != nil {
		return err
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, raw, "", "  "); err != nil {
		return err
	}
	pretty.WriteByte('\n')
	mode := os.FileMode(0o600)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".claude-probe.tmp"
	if err := os.WriteFile(tmp, pretty.Bytes(), mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// SettingsPaths are the settings.json of each config dir (default ~/.claude).
func SettingsPaths(configDirs []string) []string {
	if len(configDirs) == 0 {
		if d := os.Getenv("CLAUDE_CONFIG_DIR"); d != "" {
			configDirs = []string{d}
		} else {
			h, _ := os.UserHomeDir()
			configDirs = []string{filepath.Join(h, ".claude")}
		}
	}
	var out []string
	for _, d := range configDirs {
		out = append(out, filepath.Join(d, "settings.json"))
	}
	return out
}
