package storage

import (
	"os"
	"sort"

	"golang.org/x/sys/unix"
)

// Entry is one child of an item and what it holds (the "what is in it" list).
type Entry struct {
	Name  string `json:"name"`
	Bytes int64  `json:"bytes"`
	Own   int64  `json:"own"`
	Files int64  `json:"files"`
}

// Tally is what a walk found under one directory.
//
//   - Bytes: allocated bytes (st_blocks × 512), each inode once — what `du`
//     says, sparse files and tmpfs included.
//   - Own: the bytes only this directory holds — files whose every link is
//     inside it. A tree of hardlinks (a `cp -al` node_modules) costs almost
//     nothing, and removing it frees almost nothing: Own says so, Bytes can't.
type Tally struct {
	Bytes    int64
	Own      int64
	Files    int64
	Dirs     int64
	Newest   float64 // newest mtime of anything inside, epoch seconds
	Partial  bool    // stopped at MaxEntries
	Children []Entry // by Own, biggest first (when asked for)
}

// MaxEntries bounds one walk: past it the tally is partial.
var MaxEntries int64 = 3_000_000

type ino struct {
	size  int64
	nlink uint64
	seen  uint64
	child int
}

// Abort, when set, is asked every few thousand entries: true stops the walk
// (the tally is then partial) — a daemon shutting down doesn't wait for a
// big tree.
type Abort func() bool

type walker struct {
	abort   Abort
	root    string
	list    bool
	expand  string
	dev     uint64
	t       *Tally
	links   map[uint64]*ino
	child   []Entry
	entries int64
}

// Walk tallies the tree at root without following symlinks or crossing into
// another filesystem. With list, every child of root gets its own line in
// Children — except expand, whose own children are listed instead
// ("scratchpad/dl", "scratchpad/work", "tasks").
func Walk(root string, list bool, expand string) Tally { return WalkAbort(root, list, expand, nil) }

// WalkAbort is Walk with a way out.
func WalkAbort(root string, list bool, expand string, abort Abort) Tally {
	var st unix.Stat_t
	t := Tally{}
	if err := unix.Lstat(root, &st); err != nil {
		return t
	}
	w := &walker{dev: uint64(st.Dev), t: &t, links: map[uint64]*ino{}, root: root, list: list,
		expand: expand, abort: abort}
	w.add(&st, -1)
	if st.Mode&unix.S_IFMT == unix.S_IFDIR {
		w.dir(root, -1, "")
	}
	w.finish()
	return t
}

func (w *walker) add(st *unix.Stat_t, child int) {
	b := int64(st.Blocks) * 512
	n := uint64(st.Nlink)
	if mt := float64(st.Mtim.Sec) + float64(st.Mtim.Nsec)/1e9; mt > w.t.Newest {
		w.t.Newest = mt
	}
	isDir := st.Mode&unix.S_IFMT == unix.S_IFDIR
	if isDir {
		w.t.Dirs++
	} else {
		w.t.Files++
	}
	if child >= 0 {
		w.child[child].Files++
	}
	if isDir || n <= 1 {
		w.t.Bytes += b
		w.t.Own += b
		if child >= 0 {
			w.child[child].Bytes += b
			w.child[child].Own += b
		}
		return
	}
	// a hardlinked file: count its blocks once, and as owned only if every
	// link turns out to be inside this tree
	if l := w.links[uint64(st.Ino)]; l != nil {
		l.seen++
		return
	}
	w.links[uint64(st.Ino)] = &ino{size: b, nlink: n, seen: 1, child: child}
	w.t.Bytes += b
	if child >= 0 {
		w.child[child].Bytes += b
	}
}

func (w *walker) finish() {
	for _, l := range w.links {
		if l.seen >= l.nlink {
			w.t.Own += l.size
			if l.child >= 0 {
				w.child[l.child].Own += l.size
			}
		}
	}
	w.links = nil
	if w.list {
		sort.Slice(w.child, func(i, j int) bool {
			if w.child[i].Own != w.child[j].Own {
				return w.child[i].Own > w.child[j].Own
			}
			return w.child[i].Bytes > w.child[j].Bytes
		})
		w.t.Children = w.child
	}
}

func (w *walker) dir(path string, child int, prefix string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	names, _ := f.Readdirnames(-1)
	f.Close()
	for _, name := range names {
		if w.entries >= MaxEntries || (w.abort != nil && w.entries&4095 == 0 && w.abort()) {
			w.t.Partial = true
			return
		}
		w.entries++
		p := path + "/" + name
		var st unix.Stat_t
		if unix.Lstat(p, &st) != nil {
			continue
		}
		c, sub := child, prefix
		isDir := st.Mode&unix.S_IFMT == unix.S_IFDIR
		if w.list && child < 0 {
			if path == w.root && name == w.expand && isDir {
				sub = name + "/"
			} else {
				w.child = append(w.child, Entry{Name: prefix + name})
				c = len(w.child) - 1
			}
		}
		w.add(&st, c)
		if isDir && uint64(st.Dev) == w.dev {
			w.dir(p, c, sub)
		}
	}
}
