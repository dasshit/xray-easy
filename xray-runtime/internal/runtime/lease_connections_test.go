package runtime

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	xrayruntimev1 "xray-easy/internal/xrayruntime/api/v1"
)

type leaseTestConnection struct {
	mu       sync.Mutex
	closeErr error
	closed   int
	entered  chan struct{}
	proceed  chan struct{}
}

func (c *leaseTestConnection) Close() error {
	c.mu.Lock()
	c.closed++
	c.mu.Unlock()
	if c.entered != nil {
		close(c.entered)
		<-c.proceed
	}
	return c.closeErr
}

func (c *leaseTestConnection) closeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func TestLeaseConnectionRegistryTracksAndIdempotentlyDisconnects(t *testing.T) {
	registry := newLeaseConnectionRegistry()
	key := leaseConnectionKey{protocol: xrayruntimev1.Protocol_PROTOCOL_VLESS, email: "profile", sourceIP: netip.MustParseAddr("192.0.2.1")}
	connection := &leaseTestConnection{}
	releaseFirst := registry.register(key, connection)
	firstConnectedAt, ok := registry.connectionStart(key)
	if !ok || firstConnectedAt.IsZero() {
		t.Fatal("registry did not report a connection start time")
	}
	releaseSecond := registry.register(key, connection)
	secondConnectedAt, ok := registry.connectionStart(key)
	if !ok || !secondConnectedAt.Equal(firstConnectedAt) {
		t.Fatalf("repeated dispatch changed physical connection start time: %v, %v", firstConnectedAt, secondConnectedAt)
	}
	if got := registry.connections[key][connectionIdentity(connection)].references; got != 2 {
		t.Fatalf("references = %d, want 2", got)
	}
	releaseFirst()
	releaseFirst()
	if got := registry.connections[key][connectionIdentity(connection)].references; got != 1 {
		t.Fatalf("references after duplicate release = %d, want 1", got)
	}
	closed, alreadyApplied, err := registry.disconnect("close-1", key)
	if err != nil || alreadyApplied || closed != 1 || connection.closeCount() != 1 {
		t.Fatalf("disconnect = (%d, %t, %v), close count = %d", closed, alreadyApplied, err, connection.closeCount())
	}
	closed, alreadyApplied, err = registry.disconnect("close-1", key)
	if err != nil || !alreadyApplied || closed != 1 || connection.closeCount() != 1 {
		t.Fatalf("repeat disconnect = (%d, %t, %v), close count = %d", closed, alreadyApplied, err, connection.closeCount())
	}
	releaseSecond()
	if _, ok := registry.connectionStart(key); ok {
		t.Fatal("released connection retained an active start time")
	}
}

func TestLeaseConnectionRegistryReportsOldestActiveConnectionTime(t *testing.T) {
	registry := newLeaseConnectionRegistry()
	key := leaseConnectionKey{protocol: xrayruntimev1.Protocol_PROTOCOL_VLESS, email: "profile", sourceIP: netip.MustParseAddr("192.0.2.1")}
	first := &leaseTestConnection{}
	second := &leaseTestConnection{}
	releaseFirst := registry.register(key, first)
	firstConnectedAt, ok := registry.connectionStart(key)
	if !ok || firstConnectedAt.IsZero() {
		t.Fatal("first active connection has no start time")
	}
	time.Sleep(time.Millisecond)
	releaseSecond := registry.register(key, second)
	if got, ok := registry.connectionStart(key); !ok || !got.Equal(firstConnectedAt) {
		t.Fatalf("oldest active connection time = %v, %t; want %v", got, ok, firstConnectedAt)
	}
	releaseFirst()
	if got, ok := registry.connectionStart(key); !ok || !got.Equal(firstConnectedAt) {
		t.Fatalf("continuous lease changed its start time after one connection ended: %v, %t", got, ok)
	}
	releaseSecond()
	if _, ok := registry.connectionStart(key); ok {
		t.Fatal("inactive lease retained a connection start time")
	}
}

func TestLeaseConnectionRegistryScopesByFullIdentityAndValidatesRequests(t *testing.T) {
	registry := newLeaseConnectionRegistry()
	key := leaseConnectionKey{protocol: xrayruntimev1.Protocol_PROTOCOL_VLESS, email: "profile", sourceIP: netip.MustParseAddr("192.0.2.1")}
	other := leaseConnectionKey{protocol: key.protocol, email: key.email, sourceIP: netip.MustParseAddr("192.0.2.2")}
	connection := &leaseTestConnection{}
	registry.register(other, connection)
	closed, _, err := registry.disconnect("close-2", key)
	if err != nil || closed != 0 || connection.closeCount() != 0 {
		t.Fatalf("non-matching lease disconnect = (%d, %v), close count = %d", closed, err, connection.closeCount())
	}
	if _, _, err := registry.disconnect("", key); err == nil {
		t.Fatal("empty operation ID was accepted")
	}
	if _, _, err := registry.disconnect("x", leaseConnectionKey{protocol: key.protocol, email: "profile"}); err == nil {
		t.Fatal("invalid source IP was accepted")
	}
	if _, _, err := registry.disconnect("x", leaseConnectionKey{protocol: xrayruntimev1.Protocol_PROTOCOL_UNSPECIFIED, email: "profile", sourceIP: key.sourceIP}); err == nil {
		t.Fatal("unspecified protocol was accepted")
	}
	if _, _, err := registry.disconnect("x", leaseConnectionKey{protocol: key.protocol, sourceIP: key.sourceIP}); err == nil {
		t.Fatal("empty email was accepted")
	}
	if _, _, err := registry.disconnect("close-2", other); err == nil || err.Error() != "lease disconnect operation ID was reused for a different lease" {
		t.Fatalf("reused operation ID for a different lease error = %v", err)
	}
}

func TestLeaseConnectionRegistryHandlesCloseErrorsAndOperationEviction(t *testing.T) {
	registry := newLeaseConnectionRegistry()
	key := leaseConnectionKey{protocol: xrayruntimev1.Protocol_PROTOCOL_TROJAN, email: "profile", sourceIP: netip.MustParseAddr("2001:db8::1")}
	connection := &leaseTestConnection{closeErr: errors.New("close failed")}
	release := registry.register(key, connection)
	closed, _, err := registry.disconnect("failure", key)
	if err == nil || closed != 0 || connection.closeCount() != 1 {
		t.Fatalf("failed close = (%d, %v), close count = %d", closed, err, connection.closeCount())
	}
	release()
	for index := 0; index < leaseOperationLimit; index++ {
		id := fmt.Sprintf("evict-%d", index)
		if _, _, err := registry.disconnect(id, key); err != nil {
			t.Fatalf("disconnect operation %d: %v", index, err)
		}
	}
	if len(registry.operationIDs) != leaseOperationLimit || len(registry.operations) != leaseOperationLimit {
		t.Fatalf("operation cache size = ids:%d entries:%d", len(registry.operationIDs), len(registry.operations))
	}
	if _, exists := registry.operations["failure"]; exists {
		t.Fatal("oldest operation was not evicted")
	}
}

func TestLeaseConnectionRegistryClosesConnectionsRacingDisconnect(t *testing.T) {
	registry := newLeaseConnectionRegistry()
	key := leaseConnectionKey{protocol: xrayruntimev1.Protocol_PROTOCOL_VMESS, email: "profile", sourceIP: netip.MustParseAddr("192.0.2.4")}
	first := &leaseTestConnection{entered: make(chan struct{}), proceed: make(chan struct{})}
	registry.register(key, first)
	done := make(chan error, 1)
	go func() {
		_, _, err := registry.disconnect("race", key)
		done <- err
	}()
	<-first.entered
	second := &leaseTestConnection{}
	registry.register(key, second)
	if second.closeCount() != 1 {
		t.Fatalf("connection racing disconnect was not immediately closed: %d", second.closeCount())
	}
	close(first.proceed)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLeaseConnectionKeyFromAuthenticatedInbound(t *testing.T) {
	valid := &session.Inbound{
		Name:   "vless",
		User:   &protocol.MemoryUser{Email: "device"},
		Source: xnet.TCPDestination(xnet.ParseAddress("::ffff:192.0.2.10"), 443),
	}
	key, ok := leaseKeyFromInbound(valid)
	if !ok || key.protocol != xrayruntimev1.Protocol_PROTOCOL_VLESS || key.email != "device" || key.sourceIP.String() != "192.0.2.10" {
		t.Fatalf("valid inbound key = %+v, ok=%t", key, ok)
	}
	tests := []struct {
		name    string
		inbound *session.Inbound
	}{
		{name: "nil inbound"},
		{name: "missing user", inbound: &session.Inbound{Name: "vless"}},
		{name: "empty email", inbound: &session.Inbound{Name: "vless", User: &protocol.MemoryUser{}}},
		{name: "unknown protocol", inbound: &session.Inbound{Name: "unknown", User: &protocol.MemoryUser{Email: "x"}, Source: valid.Source}},
		{name: "no ip", inbound: &session.Inbound{Name: "vless", User: &protocol.MemoryUser{Email: "x"}}},
	}
	for _, testcase := range tests {
		t.Run(testcase.name, func(t *testing.T) {
			if _, ok := leaseKeyFromInbound(testcase.inbound); ok {
				t.Fatal("invalid inbound produced a lease key")
			}
		})
	}
}

func TestLeaseProtocolAndPointerIdentity(t *testing.T) {
	for name, want := range map[string]xrayruntimev1.Protocol{
		"vless":                  xrayruntimev1.Protocol_PROTOCOL_VLESS,
		"vmess":                  xrayruntimev1.Protocol_PROTOCOL_VMESS,
		"hysteria":               xrayruntimev1.Protocol_PROTOCOL_HYSTERIA2,
		"trojan":                 xrayruntimev1.Protocol_PROTOCOL_TROJAN,
		"shadowsocks-2022":       xrayruntimev1.Protocol_PROTOCOL_SHADOWSOCKS,
		"shadowsocks-2022-multi": xrayruntimev1.Protocol_PROTOCOL_SHADOWSOCKS,
	} {
		if got := leaseProtocol(name); got != want {
			t.Errorf("leaseProtocol(%q) = %s, want %s", name, got, want)
		}
	}
	if leaseProtocol("unknown") != xrayruntimev1.Protocol_PROTOCOL_UNSPECIFIED {
		t.Fatal("unknown protocol was accepted")
	}
	connection := &leaseTestConnection{}
	if connectionIdentity(connection) == 0 || connectionIdentity(nil) != 0 {
		t.Fatal("connection identity did not handle pointer or nil")
	}
	registry := newLeaseConnectionRegistry()
	release := registry.register(leaseConnectionKey{}, nonPointerLeaseConnection{})
	if release == nil || len(registry.connections) != 0 {
		t.Fatal("non-pointer connection was tracked")
	}
	release()
}

type nonPointerLeaseConnection struct{}

func (nonPointerLeaseConnection) Close() error { return nil }
