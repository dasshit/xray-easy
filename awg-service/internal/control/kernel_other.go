//go:build !linux

package control

import "fmt"

// KernelFactory is unavailable outside Linux, the deployment target for the AWG container.
type KernelFactory struct {
	// Options contains the network and kernel settings for the AWG device.
	Options Options
}

// Open rejects starting the TUN-backed server on unsupported operating systems.
func (KernelFactory) Open(string, int) (Device, error) {
	return nil, fmt.Errorf("AmneziaWG prototype requires Linux")
}
