// Package report reads the store: one session's calls (`report`), the
// heaviest commands across sessions (`top`), the status-line segment and the
// raw records (`export`, what the ai-agent hub pulls when no daemon runs).
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/GabrielVidal1/claude-probe/internal/plan"
	"github.com/GabrielVidal1/claude-probe/internal/shellsplit"
	"github.com/GabrielVidal1/claude-probe/internal/store"
)

// Call is the part of a stored call record the views read.
type Call struct {
	ToolUseID  string   `json:"toolUseId"`
	SessionID  string   `json:"sessionId"`
	AgentType  *string  `json:"agentType"`
	Command    string   `json:"command"`
	Status     string   `json:"status"`
	Source     string   `json:"source"`
	Background bool     `json:"background"`
	StartedAt  float64  `json:"startedAt"`
	EndedAt    *float64 `json:"endedAt"`
	DurationMs *int64   `json:"durationMs"`
	ExitCode   *int     `json:"exitCode"`
	Signal     *int     `json:"signal"`
	Totals     struct {
		CPU     float64          `json:"cpu"`
		PeakRss int64            `json:"peakRss"`
		Procs   int              `json:"procs"`
		IO      map[string]int64 `json:"io"`
		GpuS    float64          `json:"gpuS"`
	} `json:"totals"`
	Procs []struct {
		Pid       int      `json:"pid"`
		Ppid      int      `json:"ppid"`
		Depth     int      `json:"depth"`
		Label     string   `json:"label"`
		Argv      string   `json:"argv"`
		StartedAt float64  `json:"startedAt"`
		EndedAt   *float64 `json:"endedAt"`
		CPUOwn    float64  `json:"cpuOwn"`
		PeakRss   int64    `json:"peakRss"`
		ExitCode  *int     `json:"exitCode"`
		Signal    *int     `json:"signal"`
	} `json:"procs"`
}

func calls(recs []store.Record) []Call {
	out := make([]Call, 0, len(recs))
	for _, r := range recs {
		var c Call
		if json.Unmarshal(r.Data, &c) == nil {
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].StartedAt < out[j].StartedAt })
	return out
}

// Parts maps a call's processes onto its command's parts.
func Parts(c Call) []shellsplit.Part {
	ps := make([]*shellsplit.Proc, 0, len(c.Procs))
	for _, p := range c.Procs {
		sp := &shellsplit.Proc{Pid: p.Pid, Ppid: p.Ppid, Depth: p.Depth, Label: p.Label, Argv: p.Argv,
			StartedAt: p.StartedAt, CPUOwn: p.CPUOwn, PeakRss: p.PeakRss, ExitCode: p.ExitCode, Signal: p.Signal}
		if p.EndedAt != nil {
			sp.EndedAt = *p.EndedAt
		}
		ps = append(ps, sp)
	}
	return shellsplit.Components(c.Command, ps)
}

func wall(c Call) float64 {
	if c.DurationMs != nil && !c.Background {
		return float64(*c.DurationMs) / 1000
	}
	if c.EndedAt != nil {
		return *c.EndedAt - c.StartedAt
	}
	return 0
}

// CPU formats CPU seconds for one call: "8 ms", "0.42 s", "12 s", "3.1 min".
func CPU(s float64) string {
	switch {
	case s < 0.1:
		return fmt.Sprintf("%d ms", max(1, int(s*1000+0.5)))
	case s < 10:
		return fmt.Sprintf("%.2f s", s)
	case s < 60:
		return fmt.Sprintf("%.0f s", s)
	}
	return fmt.Sprintf("%.1f min", s/60)
}

// Bytes formats a size like top does (powers of 1024).
func Bytes(n int64) string {
	u := []string{"B", "KB", "MB", "GB", "TB"}
	v := float64(n)
	i := 0
	for v >= 1024 && i < len(u)-1 {
		v /= 1024
		i++
	}
	if v >= 100 || i < 2 {
		return fmt.Sprintf("%.0f %s", v, u[i])
	}
	return fmt.Sprintf("%.1f %s", v, u[i])
}

func dur(s float64) string {
	switch {
	case s <= 0:
		return ""
	case s < 1:
		return fmt.Sprintf("%d ms", int(s*1000))
	case s < 60:
		return fmt.Sprintf("%.1f s", s)
	}
	return fmt.Sprintf("%dm%02ds", int(s)/60, int(s)%60)
}

func exit(code, sig *int) string {
	switch {
	case sig != nil:
		return fmt.Sprintf("sig %d", *sig)
	case code != nil:
		return fmt.Sprint(*code)
	}
	return ""
}

func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(strings.SplitN(s, "\n", 2)[0]), " ")
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}

// Report prints one session's calls, heaviest parts under the heavy ones.
func Report(w io.Writer, st *store.Store, session string, asJSON, allParts bool) error {
	if session == "" {
		session = st.LastSession()
	}
	recs, err := st.Latest("call", session, 0)
	if err != nil {
		return err
	}
	cs := calls(recs)
	if asJSON {
		out := make([]map[string]any, 0, len(cs))
		for _, c := range cs {
			out = append(out, map[string]any{"call": c, "parts": Parts(c)})
		}
		return json.NewEncoder(w).Encode(map[string]any{"sessionId": session, "calls": out})
	}
	if len(cs) == 0 {
		fmt.Fprintf(w, "no calls recorded for session %q\n", session)
		return nil
	}
	var cpu float64
	var peak int64
	exact := 0
	for _, c := range cs {
		cpu += c.Totals.CPU
		peak = max(peak, c.Totals.PeakRss)
		if c.Source == "kernel" {
			exact++
		}
	}
	fmt.Fprintf(w, "session %s · %d calls · %s CPU · peak %s · %d/%d exact\n\n",
		session, len(cs), CPU(cpu), Bytes(peak), exact, len(cs))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', tabwriter.AlignRight)
	fmt.Fprintln(tw, "TIME\tWALL\tCPU\tPEAK\tEXIT\t COMMAND")
	for _, c := range cs {
		mark := ""
		if c.Source != "kernel" {
			mark = "~"
		}
		if c.AgentType != nil {
			mark += "[" + *c.AgentType + "] "
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t %s%s\n", time.Unix(int64(c.StartedAt), 0).Format("15:04:05"),
			dur(wall(c)), CPU(c.Totals.CPU), Bytes(c.Totals.PeakRss), exit(c.ExitCode, c.Signal),
			mark, oneLine(c.Command, 70))
		if allParts || c.Totals.CPU >= 1 {
			for _, p := range Parts(c) {
				if p.Builtin || len(p.Pids) == 0 {
					continue
				}
				code := ""
				if p.ExitCode != nil {
					code = fmt.Sprint(*p.ExitCode)
				}
				pw := 0.0
				if p.StartedAt != nil && p.EndedAt != nil {
					pw = *p.EndedAt - *p.StartedAt
				}
				fmt.Fprintf(tw, "\t%s\t%s\t%s\t%s\t   └ %s\n", dur(pw), CPU(p.CPU), Bytes(p.PeakRss), code,
					oneLine(shellsplit.Label(p), 60))
			}
		}
	}
	return tw.Flush()
}

type group struct {
	Label    string  `json:"label"`
	Count    int     `json:"count"`
	CPU      float64 `json:"cpuSeconds"`
	MaxCPU   float64 `json:"maxCpuSeconds"`
	PeakRss  int64   `json:"peakRss"`
	Wall     float64 `json:"wallSeconds"`
	Sessions int     `json:"sessions"`
	Example  string  `json:"example"`
	sids     map[string]bool
}

// Top prints the heaviest commands since `since`: by part of a command line
// (`part`), by process (`program`) or by whole call (`call`).
func Top(w io.Writer, st *store.Store, since time.Duration, by string, limit int, asJSON bool) error {
	recs, err := st.Latest("call", "", float64(time.Now().Add(-since).Unix()))
	if err != nil {
		return err
	}
	groups := map[string]*group{}
	add := func(label, sid, example string, cpu float64, peak int64, wallS float64) {
		g := groups[label]
		if g == nil {
			g = &group{Label: label, sids: map[string]bool{}}
			groups[label] = g
		}
		g.Count++
		g.CPU += cpu
		g.Wall += wallS
		g.PeakRss = max(g.PeakRss, peak)
		g.sids[sid] = true
		if cpu >= g.MaxCPU {
			g.MaxCPU, g.Example = cpu, example
		}
	}
	for _, c := range calls(recs) {
		switch by {
		case "program":
			for i, p := range c.Procs {
				if i == 0 {
					continue // the call's own shell
				}
				pw := 0.0
				if p.EndedAt != nil {
					pw = *p.EndedAt - p.StartedAt
				}
				add(p.Label, c.SessionID, p.Argv, p.CPUOwn, p.PeakRss, pw)
			}
		case "call":
			label := "bash"
			for _, p := range shellsplit.Split(c.Command) {
				if p.Program != nil {
					label = shellsplit.Label(p)
					break
				}
			}
			add(label, c.SessionID, c.Command, c.Totals.CPU, c.Totals.PeakRss, wall(c))
		default:
			for _, p := range Parts(c) {
				if len(p.Pids) == 0 {
					continue
				}
				pw := 0.0
				if p.StartedAt != nil && p.EndedAt != nil {
					pw = *p.EndedAt - *p.StartedAt
				}
				add(shellsplit.Label(p), c.SessionID, p.Text, p.CPU, p.PeakRss, pw)
			}
		}
	}
	rows := make([]*group, 0, len(groups))
	for _, g := range groups {
		g.Sessions = len(g.sids)
		rows = append(rows, g)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].CPU > rows[j].CPU })
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	if asJSON {
		return json.NewEncoder(w).Encode(map[string]any{"by": by, "since": since.String(), "rows": rows})
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', tabwriter.AlignRight)
	fmt.Fprintln(tw, "CPU\tRUNS\tMAX\tPEAK\tAVG WALL\tSESSIONS\t "+strings.ToUpper(by))
	for _, g := range rows {
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%d\t %s\n", CPU(g.CPU), g.Count, CPU(g.MaxCPU),
			Bytes(g.PeakRss), dur(g.Wall/float64(max(1, g.Count))), g.Sessions, g.Label)
	}
	return tw.Flush()
}

// Statusline is `claude-probe statusline [--wrap CMD]`: Claude Code's status
// line input on stdin. It runs the user's own status line (CMD) with the same
// input, records the official usage reading the input carries, and appends
// the segment: the session's last call — its heaviest part, CPU and peak —
// and the week's usage.
func Statusline(w io.Writer, stdin io.Reader, dbPath, wrap string) error {
	raw, _ := io.ReadAll(stdin)
	var in struct {
		SessionID  string         `json:"session_id"`
		RateLimits map[string]any `json:"rate_limits"`
	}
	_ = json.Unmarshal(raw, &in)
	base := ""
	if wrap != "" {
		cmd := exec.Command("/bin/sh", "-c", wrap)
		cmd.Stdin = bytes.NewReader(raw)
		cmd.Stderr = os.Stderr
		out, _ := cmd.Output()
		base = strings.TrimRight(string(out), "\n")
	}
	var seg []string
	if st, err := store.Open(dbPath, false); err == nil {
		defer st.Close()
		if win := plan.Windows(in.RateLimits); len(win) > 0 {
			key := plan.ConfigDir(os.Getenv("CLAUDE_CONFIG_DIR"))
			rec := map[string]any{"updatedAt": float64(time.Now().Unix()), "windows": win}
			prev := st.Newest("usage", key)
			var old map[string]any
			if prev != nil {
				_ = json.Unmarshal(prev.Data, &old)
			}
			a, _ := json.Marshal(win)
			b, _ := json.Marshal(old["windows"])
			if prev == nil || !bytes.Equal(a, b) || time.Now().Unix()-int64(prev.At) > 600 {
				_ = st.Put("usage", "", key, rec)
			}
		}
		if in.SessionID != "" {
			if recs, err := st.Latest("call", in.SessionID, 0); err == nil && len(recs) > 0 {
				cs := calls(recs)
				c := cs[len(cs)-1]
				label := oneLine(c.Command, 24)
				best := -1.0
				for _, p := range Parts(c) {
					if len(p.Pids) > 0 && p.CPU > best {
						best, label = p.CPU, shellsplit.Label(p)
					}
				}
				s := fmt.Sprintf("⚙ %s %s · %s", label, CPU(c.Totals.CPU), Bytes(c.Totals.PeakRss))
				if e := exit(c.ExitCode, c.Signal); e != "" && e != "0" {
					s += " · exit " + e
				}
				seg = append(seg, s)
			}
		}
	}
	if wk, ok := in.RateLimits["seven_day"].(map[string]any); ok && wk["used_percentage"] != nil {
		seg = append(seg, fmt.Sprintf("wk %v%%", wk["used_percentage"]))
	}
	line := strings.Join(seg, " · ")
	switch {
	case base == "":
		fmt.Fprintln(w, line)
	case line == "":
		fmt.Fprintln(w, base)
	default:
		fmt.Fprintln(w, base+" │ "+line)
	}
	return nil
}

// Export prints records after `after` — the shape of the daemon's /callmeta.
func Export(w io.Writer, st *store.Store, after int64, limit int) error {
	recs, err := st.Since(after, limit)
	if err != nil {
		return err
	}
	last := after
	if len(recs) > 0 {
		last = recs[len(recs)-1].ID
	}
	if recs == nil {
		recs = []store.Record{}
	}
	return json.NewEncoder(w).Encode(map[string]any{"records": recs, "last": last,
		"head": st.LastID(), "enabled": true})
}
