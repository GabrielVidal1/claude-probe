GO        ?= go
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -s -w -X main.version=$(VERSION)
PLATFORMS ?= linux/amd64 linux/arm64 darwin/amd64 darwin/arm64
UID       := $(shell id -u)

.PHONY: build test dist generate vmlinux

build:                      ## bin/claude-probe for this machine
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/claude-probe ./cmd/claude-probe

test:
	$(GO) vet ./... && $(GO) test ./...

dist:                       ## release binaries for $(PLATFORMS) + checksums.txt into dist/
	rm -rf dist && mkdir -p dist
	for p in $(PLATFORMS); do \
	  os=$${p%/*}; arch=$${p#*/}; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags "$(LDFLAGS)" \
	    -o dist/claude-probe-$$os-$$arch ./cmd/claude-probe || exit 1; \
	done
	cd dist && sha256sum claude-probe-* > checksums.txt

vmlinux:                    ## internal/probe/bpf/vmlinux.h from this machine's kernel BTF
	docker run --rm -u $(UID) -v /sys/kernel/btf/vmlinux:/btf:ro -v $(CURDIR):/src -w /src claude-probe-bpf:dev \
	  sh -c 'bpftool btf dump file /btf format c > internal/probe/bpf/vmlinux.h'

generate:                   ## compile the kernel program (the outputs are committed) — needs Docker
	docker build -q -t claude-probe-bpf:dev -f scripts/Dockerfile.bpf scripts
	test -f internal/probe/bpf/vmlinux.h || $(MAKE) vmlinux
	docker run --rm -u $(UID) -e HOME=/tmp -e GOCACHE=/tmp/gocache -e GOMODCACHE=/tmp/gomod \
	  -e GOFLAGS=-mod=mod -v $(CURDIR):/src -w /src/internal/probe claude-probe-bpf:dev go generate ./...
