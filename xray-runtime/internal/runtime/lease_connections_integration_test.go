package runtime

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	xrayruntimev1 "xray-easy/internal/xrayruntime/api/v1"
)

func TestEmbeddedRuntimeDisconnectsOnlySelectedVLESSSourceLease(t *testing.T) {
	proxyPort := freeEngineTCPPort(t)
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend echo server: %v", err)
	}
	defer backend.Close()
	var backendConnections sync.WaitGroup
	defer backendConnections.Wait()
	go func() {
		for {
			connection, acceptErr := backend.Accept()
			if acceptErr != nil {
				return
			}
			backendConnections.Add(1)
			go func() {
				defer backendConnections.Done()
				defer connection.Close()
				_, _ = io.Copy(connection, connection)
			}()
		}
	}()

	configuration := strings.Replace(string(vlessTestConfiguration(proxyPort)), `"listen":"127.0.0.1"`, `"listen":"::"`, 1)
	configuration = strings.Replace(configuration, `{"protocol":"freedom","tag":"direct"}`, `{"protocol":"freedom","tag":"direct","settings":{"finalRules":[{"action":"Allow"}]}}`, 1)
	engine, err := LoadEngine([]byte(configuration))
	if err != nil {
		t.Fatalf("load embedded Xray runtime: %v", err)
	}
	defer func() {
		if err := engine.Close(); err != nil {
			t.Errorf("close embedded Xray runtime: %v", err)
		}
	}()
	if err := engine.Start(); err != nil {
		t.Fatalf("start embedded Xray runtime: %v", err)
	}
	if !engine.LeaseDisconnectSupported(xrayruntimev1.Protocol_PROTOCOL_VLESS) {
		t.Fatal("VLESS connection close was not advertised")
	}
	const profile = "lease-profile"
	const credential = "12345678-1234-4234-8234-123456789012"
	if _, err := engine.AddUser(context.Background(), xrayruntimev1.Protocol_PROTOCOL_VLESS, "vless", profile, credential, ""); err != nil {
		t.Fatalf("add VLESS lease test user: %v", err)
	}
	backendAddress := backend.Addr().(*net.TCPAddr)
	first := dialVLESSLease(t, proxyPort, "127.0.0.1", profile, credential, backendAddress)
	defer first.Close()
	second := dialVLESSLease(t, proxyPort, "::1", profile, credential, backendAddress)
	defer second.Close()
	assertLeaseEcho(t, first, "first-before-close")
	assertLeaseEcho(t, second, "second-before-close")
	waitForLeaseConnections(t, engine, 2)
	telemetry, err := engine.GetTelemetry(context.Background(), map[xrayruntimev1.Protocol]string{xrayruntimev1.Protocol_PROTOCOL_VLESS: "vless"})
	if err != nil || len(telemetry) != 1 {
		t.Fatalf("read lease connection telemetry = %+v, error = %v", telemetry, err)
	}
	connectedAt := make(map[string]time.Time, 2)
	for _, observation := range telemetry[0].SourceIPs {
		connectedAt[observation.Address] = observation.ConnectedAt
	}
	if connectedAt["127.0.0.1"].IsZero() || connectedAt["::1"].IsZero() || !connectedAt["127.0.0.1"].Before(connectedAt["::1"]) {
		t.Fatalf("runtime source lease connection times = %+v", connectedAt)
	}

	closed, alreadyApplied, err := engine.DisconnectLease(context.Background(), xrayruntimev1.Protocol_PROTOCOL_VLESS, profile, "127.0.0.1", "lease-test-close-first")
	if err != nil || alreadyApplied || closed != 1 {
		t.Fatalf("disconnect first lease = (closed:%d, already:%t, err:%v)", closed, alreadyApplied, err)
	}
	if _, _, err := engine.DisconnectLease(context.Background(), xrayruntimev1.Protocol_PROTOCOL_VLESS, profile, "127.0.0.1", "lease-test-close-first"); err != nil {
		t.Fatalf("repeat idempotent lease disconnect: %v", err)
	}
	if _, _, err := engine.DisconnectLease(context.Background(), xrayruntimev1.Protocol_PROTOCOL_VLESS, profile, "::1", "lease-test-close-first"); err == nil {
		t.Fatal("operation ID reuse for another source lease was accepted")
	}
	assertConnectionClosed(t, first)
	assertLeaseEcho(t, second, "second-remains-active")

	absent, closed, flows, err := engine.RemoveUserWithProtocol(context.Background(), xrayruntimev1.Protocol_PROTOCOL_VLESS, "vless", profile)
	if err != nil || absent || closed != 1 || flows != 1 {
		t.Fatalf("remove VLESS user and close its remaining session = (absent:%t closed:%d flows:%d err:%v)", absent, closed, flows, err)
	}
	assertConnectionClosed(t, second)
}

func dialVLESSLease(t *testing.T, proxyPort int, sourceIP, email, credential string, destination *net.TCPAddr) net.Conn {
	t.Helper()
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	connection, err := dialer.Dial("tcp", net.JoinHostPort(sourceIP, strconv.Itoa(proxyPort)))
	if err != nil {
		t.Fatalf("dial VLESS inbound from %s: %v", sourceIP, err)
	}
	uuidValue, err := uuid.ParseString(credential)
	if err != nil {
		connection.Close()
		t.Fatalf("parse VLESS credential: %v", err)
	}
	request := &protocol.RequestHeader{
		Version: encoding.Version,
		Command: protocol.RequestCommandTCP,
		Port:    xnet.Port(destination.Port),
		Address: xnet.IPAddress(destination.IP),
		User: &protocol.MemoryUser{
			Email:   email,
			Account: &vless.MemoryAccount{ID: protocol.NewID(uuidValue)},
		},
	}
	if err := encoding.EncodeRequestHeader(connection, request, &encoding.Addons{}); err != nil {
		connection.Close()
		t.Fatalf("encode VLESS request: %v", err)
	}
	const bootstrap = "lease-ready"
	if _, err := io.WriteString(connection, bootstrap); err != nil {
		connection.Close()
		t.Fatalf("send initial VLESS payload: %v", err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(3 * time.Second))
	response := make([]byte, 2)
	if _, err := io.ReadFull(connection, response); err != nil {
		connection.Close()
		t.Fatalf("read VLESS response header: %v", err)
	}
	if response[0] != encoding.Version || response[1] != 0 {
		connection.Close()
		t.Fatalf("VLESS response header = %v", response)
	}
	echo := make([]byte, len(bootstrap))
	if _, err := io.ReadFull(connection, echo); err != nil || string(echo) != bootstrap {
		connection.Close()
		t.Fatalf("read initial VLESS echo %q: %v", echo, err)
	}
	_ = connection.SetReadDeadline(time.Time{})
	return connection
}

func assertLeaseEcho(t *testing.T, connection net.Conn, payload string) {
	t.Helper()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(connection, payload); err != nil {
		t.Fatalf("write lease test payload %q: %v", payload, err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, response); err != nil {
		t.Fatalf("read lease test echo %q: %v", payload, err)
	}
	if string(response) != payload {
		t.Fatalf("lease test echo = %q, want %q", response, payload)
	}
	_ = connection.SetDeadline(time.Time{})
}

func assertConnectionClosed(t *testing.T, connection net.Conn) {
	t.Helper()
	_ = connection.SetReadDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, 1)
	if _, err := connection.Read(buffer); err == nil {
		t.Fatal("selected source lease remained connected")
	}
}

func waitForLeaseConnections(t *testing.T, engine *Engine, count int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		engine.leases.mu.Lock()
		observed := 0
		for key, connections := range engine.leases.connections {
			if key.protocol == xrayruntimev1.Protocol_PROTOCOL_VLESS && key.email == "lease-profile" {
				observed += len(connections)
			}
		}
		engine.leases.mu.Unlock()
		if observed == count {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("runtime lease registry did not reach %d active connections", count)
}
