package probe

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/GabrielVidal1/claude-probe/internal/shellsplit"
)

// Programs that only run another command: labelled by the command they run.
var labelWrappers = map[string]bool{"env": true, "nohup": true, "setsid": true, "timeout": true,
	"xvfb-run": true, "rtk": true, "uvx": true, "npx": true, "time": true, "nice": true,
	"flock": true, "stdbuf": true}

// Runtimes whose own name says nothing: labelled with what they run.
var runtimes = map[string]bool{"node": true, "python": true, "python3": true, "bash": true,
	"sh": true, "zsh": true, "dash": true, "ruby": true, "perl": true, "java": true, "deno": true}
var pkgRunners = map[string]bool{"npm": true, "pnpm": true, "yarn": true, "bun": true}
var flagArgs = map[string]bool{"--with": true, "--from": true, "--python": true, "-p": true,
	"--directory": true, "--project": true, "-C": true, "--cwd": true, "--prefix": true,
	"-k": true, "-s": true, "--signal": true, "-w": true}

var (
	pyVer    = regexp.MustCompile(`^(python3?)\.\d+$`)
	timeoutN = regexp.MustCompile(`^[\d.]+[smhd]?$`)
	nodeMod  = regexp.MustCompile(`node_modules/(?:\.bin/)?((?:@[^/]+/)?[^/]+)`)
	secretRE = regexp.MustCompile(`(?i)((?:token|secret|password|passwd|api[_-]?key|authorization)` +
		`["']?\s*[:=\s]\s*(?:bearer\s+|basic\s+)?|bearer\s+)["']?[^\s"']{6,}`)
	rtkRE = regexp.MustCompile(`(^|[\s;&|(]|\$\()rtk\s+(?:proxy\s+)?`)
)

// Label is a short, stable name for what a process is — `vite`, `npm run
// build`, `python3 -m http.server`, `chrome (renderer)`.
func Label(argv []string, comm string) string {
	if len(argv) == 0 {
		return comm
	}
	if len(argv) == 1 && strings.Contains(argv[0], " ") {
		argv = strings.Fields(argv[0]) // a rewritten process title
	}
	prog := pyVer.ReplaceAllString(filepath.Base(argv[0]), "$1")
	rest := argv[1:]
	if prog == "uv" && len(rest) > 0 && rest[0] == "run" {
		prog, rest = "uvx", rest[1:]
	}
	if prog == "rtk" && len(rest) > 0 && rest[0] == "proxy" {
		rest = rest[1:]
	}
	if labelWrappers[prog] {
		i := 0
		for i < len(rest) && (strings.HasPrefix(rest[i], "-") || strings.Contains(rest[i], "=") ||
			(prog == "timeout" && timeoutN.MatchString(rest[i]))) {
			if flagArgs[rest[i]] {
				i += 2
			} else {
				i++
			}
		}
		if prog == "flock" && i < len(rest) {
			i++
		}
		if i < len(rest) {
			return Label(rest[i:], comm)
		}
		return prog
	}
	if pkgRunners[prog] {
		out := []string{prog}
		for _, a := range rest[:min(3, len(rest))] {
			if !strings.HasPrefix(a, "-") && len(out) < 3 {
				out = append(out, a)
			}
		}
		return strings.Join(out, " ")
	}
	if !runtimes[prog] {
		for _, a := range rest {
			if strings.HasPrefix(a, "--type=") {
				return prog + " (" + a[7:] + ")"
			}
		}
		return prog
	}
	for i, a := range rest {
		if a == "-m" && i+1 < len(rest) {
			return prog + " -m " + rest[i+1]
		}
		if a == "-c" || a == "-e" { // an inline script: its text says nothing stable
			return prog + " " + a
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		if m := nodeMod.FindStringSubmatch(a); m != nil {
			return m[1]
		}
		b := filepath.Base(strings.TrimRight(a, "/"))
		if b == "" || b == "." {
			b = a
		}
		return prog + " " + b
	}
	return prog
}

// ToolCommand is the command a Claude Bash-tool shell runs (its `eval '…'`),
// tolerating a command line the kernel cut short; "" if argv isn't one.
func ToolCommand(argv []string) string {
	if len(argv) < 3 {
		return ""
	}
	sh := filepath.Base(argv[0])
	if sh != "bash" && sh != "sh" && sh != "zsh" {
		return ""
	}
	hasC := false
	for _, a := range argv[1:min(3, len(argv))] {
		if a == "-c" {
			hasC = true
		}
	}
	if !hasC {
		return ""
	}
	last := argv[len(argv)-1]
	i := strings.Index(last, "eval '")
	if i < 0 {
		return ""
	}
	return unquoteEval(last[i+6:])
}

// unquoteEval reads a single-quoted shell word from its first character on:
// a quote inside it is written '\” or '"'"' (what Claude Code uses); a
// command line the kernel cut short simply ends early.
func unquoteEval(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '\'' {
			b.WriteByte(s[i])
			i++
			continue
		}
		switch {
		case strings.HasPrefix(s[i:], `'\''`):
			b.WriteByte('\'')
			i += 4
		case strings.HasPrefix(s[i:], `'"'"'`):
			b.WriteByte('\'')
			i += 5
		default:
			return b.String()
		}
	}
	return b.String()
}

// CommandLabel labels a shell command line by its first part that runs a
// program: `cd x && npm run build 2>&1 | tail` is `npm run build`.
func CommandLabel(cmd string) string {
	for _, p := range shellsplit.Split(cmd) {
		if p.Program != nil {
			words := strings.Fields(p.Text)
			for i, w := range words {
				if filepath.Base(w) == *p.Program {
					return trim(Label(words[i:], *p.Program), 60)
				}
			}
			return trim(*p.Program, 60)
		}
	}
	f := strings.Fields(cmd)
	if len(f) == 0 {
		return "bash"
	}
	return trim(filepath.Base(f[0]), 60)
}

// NormCommand is a command as matched between the pre hook (before rtk's
// rewrite) and the shell's eval (after): rtk dropped, blanks collapsed.
func NormCommand(cmd string) string {
	return strings.Join(strings.Fields(rtkRE.ReplaceAllString(cmd, "$1")), " ")
}

// Redact hides what looks like a secret in a command line.
func Redact(s string) string {
	return trim(secretRE.ReplaceAllString(s, "$1…"), 400)
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// ArgvOf is a process's command line (debugging).
func ArgvOf(pid int) []string { return argvOf(pid) }
