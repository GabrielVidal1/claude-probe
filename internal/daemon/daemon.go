// Package daemon runs the probe: one per user, started on demand by the
// first hook (it exits after Idle without a call or an event), or kept up by
// whoever runs `claude-probe daemon --idle 0`.
//
// It listens on a unix socket (0600) for the hooks' events and serves the
// records over HTTP on the same socket:
//
//	POST /event               one hook event (JSON)
//	GET  /callmeta?after=N    records after id N — the ai-agent hub's pull
//	GET  /health              version, mode (kernel | sampled), calls running
//	POST /storage/scan        measure every tracked item now (waits for it)
//	POST /storage/rm          remove a scratch dir or a worktree, safely
//	                          ({"path", "force", "dry"} → the removal)
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/GabrielVidal1/claude-probe/internal/caps"
	"github.com/GabrielVidal1/claude-probe/internal/paths"
	"github.com/GabrielVidal1/claude-probe/internal/probe"
	"github.com/GabrielVidal1/claude-probe/internal/storage"
	"github.com/GabrielVidal1/claude-probe/internal/store"
)

type Options struct {
	Idle      time.Duration // 0 = never exit
	NoKernel  bool
	NoStorage bool          // don't track what sessions keep on disk
	ScanDelay time.Duration // before the first storage pass
	Version   string
}

var ErrRunning = errors.New("another daemon is running")

// Run serves until a signal, or until it has been idle for opts.Idle.
func Run(opts Options) error {
	if err := paths.Ensure(); err != nil {
		return err
	}
	unlock, err := lock(paths.Lock())
	if err != nil {
		return ErrRunning
	}
	defer unlock()
	st, err := store.Open(paths.DB(), false)
	if err != nil {
		return err
	}
	defer st.Close()

	mode, note := "sampled", ""
	var feed *probe.Feed
	if !opts.NoKernel {
		f := probe.NewFeed()
		if k, err := probe.StartKernel(f, uint32(os.Getuid())); err == nil {
			defer k.Close()
			feed, mode = f, "kernel"
			for _, n := range k.Notes {
				log.Print(n)
			}
		} else {
			note = err.Error()
			log.Printf("kernel layer off (%v): sampling /proc", err)
		}
	}
	caps.Drop() // the kernel program is loaded: nothing else needs privileges
	pr := probe.New(st, feed)
	var sc *storage.Scanner
	if !opts.NoStorage {
		sc = storage.New(st)
		pr.OnEvent = func(ev probe.Event) {
			sc.Touch(ev.Sid, ev.Cwd, ev.ConfigDir, ev.TmpDir, ev.E == "stop" || ev.E == "subStop")
		}
		pr.OnDone = sc.CallDone
		sc.Start(opts.ScanDelay)
		defer sc.Stop()
	}
	started := time.Now()

	sock := paths.Socket()
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	_ = os.Chmod(sock, 0o600)
	defer os.Remove(sock)

	wake := make(chan struct{}, 1)
	poke := func() {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /event", func(w http.ResponseWriter, r *http.Request) {
		var ev probe.Event
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&ev); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		pr.Handle(ev)
		poke()
		w.WriteHeader(204)
	})
	mux.HandleFunc("GET /callmeta", func(w http.ResponseWriter, r *http.Request) {
		after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 || limit > 2000 {
			limit = 500
		}
		recs, err := st.Since(after, limit)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		last := after
		if len(recs) > 0 {
			last = recs[len(recs)-1].ID
		}
		if recs == nil {
			recs = []store.Record{}
		}
		writeJSON(w, map[string]any{"records": recs, "last": last, "head": st.LastID(),
			"enabled": true, "hz": probe.Hz, "running": pr.Running(), "mode": mode})
	})
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"version": opts.Version, "mode": mode, "note": note,
			"running": pr.Running(), "since": started.Unix(), "pid": os.Getpid(), "storage": sc != nil})
	})
	mux.HandleFunc("POST /storage/scan", func(w http.ResponseWriter, r *http.Request) {
		if sc == nil {
			http.Error(w, "storage tracking is off", 404)
			return
		}
		writeJSON(w, map[string]any{"done": sc.Scan(10 * time.Minute)})
	})
	mux.HandleFunc("POST /storage/rm", func(w http.ResponseWriter, r *http.Request) {
		if sc == nil {
			http.Error(w, "storage tracking is off", 404)
			return
		}
		var q struct {
			Path  string `json:"path"`
			Force bool   `json:"force"`
			Dry   bool   `json:"dry"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&q); err != nil || q.Path == "" {
			http.Error(w, "want {path, force, dry}", 400)
			return
		}
		out, err := sc.RemoveNow(q.Path, q.Force, q.Dry, 5*time.Minute)
		res := map[string]any{"removal": out, "ok": err == nil}
		if err != nil {
			res["error"] = err.Error()
			res["unsafe"] = errors.Is(err, storage.ErrUnsafe)
		}
		writeJSON(w, res)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Shutdown(context.Background())
	log.Printf("claude-probe %s: %s mode, listening on %s", opts.Version, mode, sock)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	timer := time.NewTimer(0)
	for {
		select {
		case <-sig:
			return nil
		case <-wake:
		case <-timer.C:
		}
		next := pr.Tick()
		if opts.Idle > 0 && pr.Running() == 0 && time.Since(unix(pr.LastEvent)) > opts.Idle {
			log.Printf("idle for %s: exiting", opts.Idle)
			return nil
		}
		d := time.Until(unix(next))
		if d < 5*time.Millisecond {
			d = 5 * time.Millisecond
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(d)
	}
}

func unix(f float64) time.Time {
	return time.Unix(0, int64(f*1e9))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func lock(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, err
	}
	_ = f.Truncate(0)
	_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
	return func() { f.Close() }, nil
}
