//go:build !linux

package caps

func Drop()                               {}
func Effective() bool                     { return false }
func FileCaps(string) (bpf, perfmon bool) { return false, false }
