package probe

// The kernel program, compiled once for both architectures (CO-RE: it is
// relocated against the running kernel's BTF at load). Needs clang +
// libbpf headers + vmlinux.h — run `make generate`, which does it in a
// container; the outputs are committed.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64,arm64 probe bpf/probe.bpf.c -- -I./bpf -O2 -g -Wall
