// Package hook is `claude-probe hook`: the Claude Code hook on PreToolUse /
// PostToolUse (Bash), UserPromptSubmit, Stop, SubagentStart and
// SubagentStop. It hands the event to the daemon and exits — fire and
// forget, never fails the call. When no daemon answers it starts one and
// retries for up to a second.
//
// It prints nothing — a UserPromptSubmit hook's stdout lands in the model's
// context — except one line on a prompt when a filesystem the session writes
// to is nearly full (storage.NudgeLine; `storage config --nudge-at`).
package hook

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/GabrielVidal1/claude-probe/internal/paths"
	"github.com/GabrielVidal1/claude-probe/internal/probe"
	"github.com/GabrielVidal1/claude-probe/internal/storage"
)

var events = map[string]string{"PreToolUse": "pre", "PostToolUse": "post",
	"UserPromptSubmit": "prompt", "Stop": "stop", "SubagentStart": "subStart",
	"SubagentStop": "subStop"}

// Event turns a hook's stdin into the daemon's event (nil: not ours).
func Event(in map[string]any) *probe.Event {
	e := events[str(in["hook_event_name"])]
	if e == "" {
		return nil
	}
	tool := str(in["tool_name"])
	if (e == "pre" || e == "post") && tool != "Bash" && !probe.FileTools[tool] {
		return nil
	}
	ev := &probe.Event{E: e, T: float64(time.Now().UnixNano()) / 1e9, Sid: str(in["session_id"]),
		PromptID: str(in["prompt_id"]), AgentID: str(in["agent_id"]),
		AgentType: str(in["agent_type"]), Cwd: str(in["cwd"]), Effort: str(in["effort"]),
		ConfigDir: os.Getenv("CLAUDE_CONFIG_DIR"), TmpDir: os.Getenv("CLAUDE_CODE_TMPDIR")}
	inp, _ := in["tool_input"].(map[string]any)
	if (e == "pre" || e == "post") && probe.FileTools[tool] {
		ev.Tid, ev.Tool = str(in["tool_use_id"]), tool
		ev.FilePath = str(inp["file_path"])
		if ev.FilePath == "" {
			ev.FilePath = str(inp["notebook_path"])
		}
		if ev.FilePath != "" && !filepath.IsAbs(ev.FilePath) && ev.Cwd != "" {
			ev.FilePath = filepath.Join(ev.Cwd, ev.FilePath)
		}
		ev.File = statFile(ev.FilePath) // before the tool writes (pre), after (post)
		if e == "post" {
			if d, ok := in["duration_ms"].(float64); ok {
				v := int64(d)
				ev.DurationMs = &v
			}
		}
		return ev
	}
	if e == "pre" || e == "post" {
		ev.Tid, ev.Tool, ev.Command = str(in["tool_use_id"]), str(in["tool_name"]), str(inp["command"])
		ev.Bg, _ = inp["run_in_background"].(bool)
	}
	if e == "pre" {
		ev.Chain = chain()
	}
	if e == "post" {
		if d, ok := in["duration_ms"].(float64); ok {
			v := int64(d)
			ev.DurationMs = &v
		}
		if resp, ok := in["tool_response"].(map[string]any); ok {
			ev.BgTask = str(resp["backgroundTaskId"])
			ev.Interrupted, _ = resp["interrupted"].(bool)
		}
	}
	if e == "stop" || e == "subStop" {
		if bt, ok := in["background_tasks"].([]any); ok {
			n := len(bt)
			ev.BgTasks = &n
		}
	}
	return ev
}

// statFile is a file's size now, for a file tool's before / after.
func statFile(p string) *probe.FStat {
	if p == "" {
		return nil
	}
	var st unix.Stat_t
	if unix.Stat(p, &st) != nil {
		return &probe.FStat{}
	}
	return &probe.FStat{Exists: true, Bytes: int64(st.Blocks) * 512, Size: st.Size}
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// chain is this hook's ancestors, nearest first (the CLI runs hooks through
// a short-lived shell, gone before the daemon could walk it itself).
func chain() []int {
	var out []int
	pid := os.Getppid()
	for i := 0; i < 6 && pid > 1; i++ {
		out = append(out, pid)
		pid = probe.ParentOf(pid)
	}
	return out
}

func client() *http.Client {
	sock := paths.Socket()
	return &http.Client{Timeout: 500 * time.Millisecond, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}}}
}

func send(c *http.Client, body []byte) error {
	resp, err := c.Post("http://probe/event", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// Run is the hook's whole life. self is this binary's path; out is where a
// prompt's nudge goes (the hook's stdout).
func Run(stdin io.Reader, out io.Writer, self string) {
	var in map[string]any
	if json.NewDecoder(stdin).Decode(&in) != nil {
		return
	}
	ev := Event(in)
	if ev == nil {
		return
	}
	if ev.E == "prompt" && out != nil {
		if line := storage.NudgeLine(ev.Sid, ev.Cwd, ev.TmpDir); line != "" {
			io.WriteString(out, line+"\n")
		}
	}
	body, _ := json.Marshal(ev)
	c := client()
	if send(c, body) == nil {
		return
	}
	if os.Getenv("CLAUDE_PROBE_NO_SPAWN") != "" {
		return
	}
	spawn(self)
	for i := 0; i < 20; i++ {
		time.Sleep(50 * time.Millisecond)
		if send(c, body) == nil {
			return
		}
	}
}

// spawn starts the daemon detached (its own session; it outlives the hook).
func spawn(self string) {
	_ = paths.Ensure()
	logf, err := os.OpenFile(paths.Log(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer logf.Close()
	cmd := exec.Command(self, "daemon", "--idle", "30m")
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if cmd.Start() == nil {
		_ = cmd.Process.Release()
	}
}
