//go:build !linux

package control

import (
	"strings"
	"testing"
)

func TestKernelFactoryRejectsUnsupportedOperatingSystems(t *testing.T) {
	if _, err := (KernelFactory{}).Open("awg0", 1280); err == nil || !strings.Contains(err.Error(), "requires Linux") {
		t.Fatalf("unsupported kernel factory error = %v", err)
	}
}
