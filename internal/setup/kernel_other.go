//go:build !linux

package setup

import "errors"

const DefaultKernelPath = ""

// SetupKernel is Linux-only: macOS needs no setup (the kqueue layer runs as
// the user).
func SetupKernel(self, target string, remove bool) error {
	return errors.New("nothing to set up here: on macOS claude-probe sees every process without privileges")
}
