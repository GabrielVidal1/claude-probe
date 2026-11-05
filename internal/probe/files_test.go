package probe

import "testing"

func TestFileAgg(t *testing.T) {
	MB := int64(1 << 20)
	evs := []FileEv{
		// a log appended three times: one file
		{T: 1, Op: "write", Path: "/w/app/out.log", Created: true, Delta: 4096, DSize: 100, Size: 100, Ino: 1, Dev: 9},
		{T: 2, Op: "write", Path: "/w/app/out.log", Delta: 4096, DSize: 5000, Size: 5100, Ino: 1, Dev: 9},
		{T: 3, Op: "write", Path: "/w/app/out.log", Delta: 0, DSize: 10, Size: 5110, Ino: 1, Dev: 9},
		// an install: many files under node_modules
		{T: 4, Op: "write", Path: "/w/app/node_modules/a/index.js", Created: true, Delta: 3 * MB, Size: 3 * MB, Ino: 2, Dev: 9},
		{T: 4, Op: "write", Path: "/w/app/node_modules/b/lib/x.js", Created: true, Delta: 2 * MB, Size: 2 * MB, Ino: 3, Dev: 9},
		// a temp file written then deleted: nets out
		{T: 5, Op: "write", Path: "/tmp/t.bin", Created: true, Delta: 10 * MB, Size: 10 * MB, Ino: 4, Dev: 8},
		{T: 6, Op: "unlink", Path: "…/tmp/t.bin", Delta: -10 * MB, DSize: -10 * MB, Ino: 4, Dev: 8},
		// Claude Code's own cwd file: never counted
		{T: 7, Op: "write", Path: "/tmp/claude-00ca-cwd", Created: true, Delta: 4096, Size: 96, Ino: 5, Dev: 8},
		// an unlink completed by a write in the same directory
		{T: 8, Op: "unlink", Path: "…/w/app/old.bin", Delta: -MB, DSize: -MB, Ino: 6, Dev: 9},
	}
	a := fileAgg(evs)
	if a["written"].(int64) != 8192+15*MB || a["freed"].(int64) != 11*MB {
		t.Fatalf("written/freed: %v", a)
	}
	if a["net"].(int64) != 8192+4*MB || a["files"].(int) != 5 || a["created"].(int) != 4 || a["deleted"].(int) != 2 {
		t.Fatalf("totals: %v", a)
	}
	found := false
	for _, f := range a["top"].([]map[string]any) {
		found = found || f["path"] == "/w/app/old.bin"
	}
	if !found {
		t.Fatalf("the unlink wasn't given its full path: %v", a["top"])
	}
	top := a["top"].([]map[string]any)
	if top[0]["path"] != "/w/app/node_modules/a/index.js" {
		t.Fatalf("biggest first: %v", top)
	}
	for _, f := range top {
		if f["path"] == "/tmp/t.bin" {
			t.Fatalf("a file that netted out is still listed: %v", f)
		}
	}
	dirs := a["dirs"].([]map[string]any)
	if dirs[0]["dir"] != "/w/app/node_modules" || dirs[0]["files"].(int64) != 2 {
		t.Fatalf("an install groups under node_modules: %v", dirs)
	}
	if fileAgg(nil) != nil {
		t.Fatal("no events: no record")
	}
}
