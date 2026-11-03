//go:build !linux && !darwin

package probe

import "errors"

// Kernel is the eBPF layer — Linux only; elsewhere the probe samples.
type Kernel struct{ Notes []string }

func StartKernel(*Feed, uint32) (*Kernel, error) {
	return nil, errors.New("the kernel layer is Linux-only")
}

func (k *Kernel) Close() {}
