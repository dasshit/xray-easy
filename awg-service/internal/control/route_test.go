package control

import "testing"

func TestRouteDeviceFindsIPv4AndIPv6EgressInterfaces(t *testing.T) {
	for _, route := range []struct {
		output string
		want   string
	}{
		{"1.1.1.1 via 172.20.0.1 dev eth1 src 172.20.0.2 uid 10001", "eth1"},
		{"2606:4700:4700::1111 via fd00::1 dev eth2 src fd00::2 metric 100", "eth2"},
	} {
		got, err := routeDevice(route.output)
		if err != nil {
			t.Fatalf("routeDevice(%q): %v", route.output, err)
		}
		if got != route.want {
			t.Errorf("routeDevice(%q) = %q, want %q", route.output, got, route.want)
		}
	}
}

func TestRouteDeviceRequiresInterface(t *testing.T) {
	if _, err := routeDevice("unreachable 2606:4700::1"); err == nil {
		t.Fatal("route without an egress interface was accepted")
	}
}
