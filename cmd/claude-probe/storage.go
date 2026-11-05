package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/GabrielVidal1/claude-probe/internal/paths"
	"github.com/GabrielVidal1/claude-probe/internal/report"
	"github.com/GabrielVidal1/claude-probe/internal/storage"
	"github.com/GabrielVidal1/claude-probe/internal/store"
)

func runStorage(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "rm":
			return runStorageRm(args[1:])
		case "clean":
			return runStorageClean(args[1:])
		case "config":
			return runStorageConfig(args[1:])
		case "ls":
			args = args[1:]
		}
	}
	fs := flag.NewFlagSet("storage", flag.ExitOnError)
	session := fs.String("session", "", "one session's items (id or prefix)")
	kind := fs.String("kind", "", "scratchpad | worktree | transcript | root")
	limit := fs.Int("limit", 20, "items (0: all)")
	asJSON := fs.Bool("json", false, "JSON output")
	scan := fs.Bool("scan", false, "measure everything now first")
	_ = fs.Parse(args)
	if *scan {
		if err := scanNow(); err != nil {
			return err
		}
	}
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	v, err := report.LoadStorage(st)
	if err != nil {
		return err
	}
	return report.Storage(os.Stdout, v.Filter(*session, *kind), *limit, *asJSON)
}

// daemonPost calls the daemon's API; errNoDaemon when none answers.
var errNoDaemon = errors.New("no daemon")

func daemonPost(path string, body any, timeout time.Duration) (map[string]any, error) {
	raw, _ := json.Marshal(body)
	resp, err := sockClient(timeout).Post("http://probe"+path, "application/json", bytes.NewReader(raw))
	if err != nil {
		return nil, errNoDaemon
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 404 {
		return nil, errNoDaemon // an older daemon, or storage tracking off
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("daemon: %s", strings.TrimSpace(string(b)))
	}
	var out map[string]any
	return out, json.Unmarshal(b, &out)
}

// localScanner is a scanner in this process, for when no daemon runs.
func localScanner() (*storage.Scanner, *store.Store, error) {
	st, err := store.Open(paths.DB(), false)
	if err != nil {
		return nil, nil, err
	}
	sc := storage.New(st)
	sc.Load()
	return sc, st, nil
}

func scanNow() error {
	fmt.Fprintln(os.Stderr, "measuring…")
	if _, err := daemonPost("/storage/scan", nil, 15*time.Minute); err != errNoDaemon {
		return err
	}
	sc, st, err := localScanner()
	if err != nil {
		return err
	}
	defer st.Close()
	sc.Pass(true)
	return nil
}

func remove(path string, force, dry bool) (storage.Removal, error) {
	abs, _ := filepath.Abs(path)
	out, err := daemonPost("/storage/rm", map[string]any{"path": abs, "force": force, "dry": dry}, 6*time.Minute)
	if err == nil {
		var r storage.Removal
		raw, _ := json.Marshal(out["removal"])
		_ = json.Unmarshal(raw, &r)
		if ok, _ := out["ok"].(bool); !ok {
			msg, _ := out["error"].(string)
			return r, errors.New(msg)
		}
		return r, nil
	}
	if err != errNoDaemon {
		return storage.Removal{Path: abs}, err
	}
	sc, st, err := localScanner()
	if err != nil {
		return storage.Removal{Path: abs}, err
	}
	defer st.Close()
	sc.Pass(false) // know the items, so the removal is recorded
	return sc.Remove(abs, force, dry)
}

func runStorageRm(args []string) error {
	fs := flag.NewFlagSet("storage rm", flag.ExitOnError)
	force := fs.Bool("force", false, "even with uncommitted changes, unmerged commits or a live session")
	dry := fs.Bool("dry-run", false, "say what would happen")
	_ = fs.Parse(reorder(args))
	if fs.NArg() == 0 {
		return errors.New("storage rm: which path? (`claude-probe storage` lists them)")
	}
	failed := 0
	for _, p := range fs.Args() {
		r, err := remove(p, *force, *dry)
		if err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "kept %s: %v\n", report.Tilde(p), err)
			continue
		}
		verb := "removed"
		if *dry {
			verb = "would remove"
		}
		line := fmt.Sprintf("%s %s %s (%s)", verb, r.Kind, report.Tilde(r.Path), report.Bytes(r.Freed))
		if r.Note != "" {
			line += " — " + r.Note
		}
		fmt.Println(line)
	}
	if failed > 0 {
		return fmt.Errorf("%d kept", failed)
	}
	return nil
}

func runStorageClean(args []string) error {
	fs := flag.NewFlagSet("storage clean", flag.ExitOnError)
	scratch := fs.Float64("scratch", 3, "scratch dirs of sessions quiet this many days (0: none)")
	wts := fs.Float64("worktrees", 3, "merged, clean worktrees idle this many days (0: none)")
	yes := fs.Bool("yes", false, "remove them (default: a dry run)")
	_ = fs.Parse(args)
	st, err := openStore()
	if err != nil {
		return err
	}
	v, err := report.LoadStorage(st)
	st.Close()
	if err != nil {
		return err
	}
	now := float64(time.Now().Unix())
	var picks []storage.Item
	for _, it := range v.Items {
		switch {
		case it.Kind == "scratchpad" && *scratch > 0 && now-it.NewestAt >= *scratch*86400:
			picks = append(picks, it)
		case it.Kind == "worktree" && *wts > 0 && it.Git != nil && it.Git.Merged != nil && *it.Git.Merged &&
			it.Git.Dirty != nil && *it.Git.Dirty == 0 &&
			float64(it.Git.IdleFor)+(now-it.Git.At) >= *wts*86400:
			picks = append(picks, it)
		}
	}
	if len(picks) == 0 {
		fmt.Println("nothing to clean")
		return nil
	}
	var total int64
	kept := 0
	for _, it := range picks {
		r, err := remove(it.Path, false, !*yes)
		if err != nil {
			kept++
			fmt.Fprintf(os.Stderr, "kept %s: %v\n", report.Tilde(it.Path), err)
			continue
		}
		total += r.Freed
		verb := "removed"
		if !*yes {
			verb = "would remove"
		}
		fmt.Printf("%s %-10s %8s  %s\n", verb, it.Kind, report.Bytes(it.Own), report.Tilde(it.Path))
	}
	if *yes {
		fmt.Printf("freed %s", report.Bytes(total))
	} else {
		fmt.Printf("would free %s — run again with --yes", report.Bytes(total))
	}
	if kept > 0 {
		fmt.Printf(" (%d kept)", kept)
	}
	fmt.Println()
	return nil
}

func runStorageConfig(args []string) error {
	fs := flag.NewFlagSet("storage config", flag.ExitOnError)
	root := fs.String("root", "", "a directory to track as one item")
	label := fs.String("label", "", "its name (with --root)")
	wroot := fs.String("worktree-root", "", "a directory whose children are git worktrees")
	rm := fs.String("rm-root", "", "stop tracking this directory")
	auto := fs.String("auto-clean", "", "the daemon removes scratch dirs of sessions quiet this many days (0: off)")
	nudge := fs.String("nudge-at", "", "tell the agent when its disk is this full (e.g. 90%, 0.9; off)")
	asJSON := fs.Bool("json", false, "JSON output")
	_ = fs.Parse(args)
	c := storage.LoadConfig()
	changed := false
	abs := func(p string) string {
		if strings.HasPrefix(p, "~/") {
			return p
		}
		a, _ := filepath.Abs(p)
		return a
	}
	drop := func(p string) {
		out := c.Roots[:0]
		for _, r := range c.Roots {
			if r.Path != p {
				out = append(out, r)
			}
		}
		c.Roots = out
	}
	if *root != "" {
		p := abs(*root)
		drop(p)
		c.Roots = append(c.Roots, storage.Root{Path: p, Label: *label})
		changed = true
	}
	if *wroot != "" {
		p := abs(*wroot)
		drop(p)
		c.Roots = append(c.Roots, storage.Root{Path: p, Worktrees: true})
		changed = true
	}
	if *rm != "" {
		drop(abs(*rm))
		changed = true
	}
	if *auto != "" {
		var d float64
		if _, err := fmt.Sscanf(strings.TrimSuffix(*auto, "d"), "%g", &d); err != nil && *auto != "off" {
			return fmt.Errorf("--auto-clean: a number of days, or 0/off")
		}
		c.Clean.ScratchAfterDays = d
		changed = true
	}
	if *nudge != "" {
		v := strings.TrimSuffix(*nudge, "%")
		var f float64
		if *nudge == "off" || *nudge == "0" {
			f = -1
		} else if _, err := fmt.Sscanf(v, "%g", &f); err != nil || f <= 0 {
			return fmt.Errorf("--nudge-at: a fill level (90%%, 0.9) or off")
		} else if f > 1 {
			f /= 100
		}
		c.NudgeAt = f
		changed = true
	}
	if changed {
		if err := storage.SaveConfig(c); err != nil {
			return err
		}
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(c)
	}
	fmt.Println("config:", storage.ConfigPath())
	for _, r := range c.Roots {
		kind := "item"
		if r.Worktrees {
			kind = "worktrees under"
		}
		fmt.Printf("  %s %s %s\n", kind, r.Path, r.Label)
	}
	if c.Clean.On() {
		fmt.Printf("  auto-clean: scratch dirs of sessions quiet %g days\n", c.Clean.ScratchAfterDays)
	} else {
		fmt.Println("  auto-clean: off")
	}
	if n := c.Nudge(); n > 0 {
		fmt.Printf("  nudge: a line in the agent's context when its disk is %.0f%% full\n", n*100)
	} else {
		fmt.Println("  nudge: off")
	}
	return nil
}
