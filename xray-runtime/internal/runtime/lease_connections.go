package runtime

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"
	xrayruntimev1 "xray-easy/internal/xrayruntime/api/v1"
)

// leaseOperationLimit bounds cached disconnect results for idempotent retries.
const leaseOperationLimit = 2048

// leaseConnectionKey identifies one observed source-IP lease.
type leaseConnectionKey struct {
	protocol xrayruntimev1.Protocol
	email    string
	sourceIP netip.Addr
}

// leaseConnection stores one physical client connection and its active dispatch references.
type leaseConnection struct {
	connection interface{ Close() error }
	references int
}

// leaseDisconnectResult is the result cached for an idempotent disconnect request.
type leaseDisconnectResult struct {
	closed int
	err    error
	key    leaseConnectionKey
}

// leaseConnectionRegistry tracks closable authenticated inbound connections.
type leaseConnectionRegistry struct {
	mu           sync.Mutex
	connections  map[leaseConnectionKey]map[uintptr]*leaseConnection
	connectedAt  map[leaseConnectionKey]time.Time
	closing      map[leaseConnectionKey]bool
	operations   map[string]leaseDisconnectResult
	operationIDs []string
}

// newLeaseConnectionRegistry creates an empty authenticated-connection registry.
func newLeaseConnectionRegistry() *leaseConnectionRegistry {
	return &leaseConnectionRegistry{
		connections: make(map[leaseConnectionKey]map[uintptr]*leaseConnection),
		connectedAt: make(map[leaseConnectionKey]time.Time),
		closing:     make(map[leaseConnectionKey]bool),
		operations:  make(map[string]leaseDisconnectResult),
	}
}

// installLeaseTracking wraps the configured outbound handlers so each authenticated Xray dispatch
// registers its parent client connection for exact source-lease termination.
func installLeaseTracking(instance *core.Instance, registry *leaseConnectionRegistry) (bool, error) {
	if instance == nil || registry == nil {
		return false, errors.New("Xray instance and lease registry are required")
	}
	manager, ok := instance.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if !ok || manager == nil {
		return false, errors.New("Xray outbound manager is unavailable")
	}

	handlers := manager.ListHandlers(context.Background())
	if len(handlers) == 0 {
		return false, nil
	}
	defaultHandler := manager.GetDefaultHandler()
	if defaultHandler == nil || defaultHandler.Tag() == "" {
		// Minimal validation fixtures and external Xray configurations may omit a
		// tagged outbound. They remain runnable, but have no lease-close capability.
		return false, nil
	}
	ordered := make([]outbound.Handler, 0, len(handlers))
	ordered = append(ordered, defaultHandler)
	for _, handler := range handlers {
		if handler == nil || handler.Tag() == defaultHandler.Tag() {
			continue
		}
		if handler.Tag() == "" {
			continue
		}
		ordered = append(ordered, handler)
	}
	for _, handler := range ordered {
		if err := manager.RemoveHandler(context.Background(), handler.Tag()); err != nil {
			return false, fmt.Errorf("remove outbound %q for lease wrapping: %w", handler.Tag(), err)
		}
	}
	for _, handler := range ordered {
		if err := manager.AddHandler(context.Background(), &leaseTrackedOutbound{Handler: handler, registry: registry}); err != nil {
			return false, fmt.Errorf("wrap outbound %q for lease tracking: %w", handler.Tag(), err)
		}
	}
	return true, nil
}

// leaseTrackedOutbound registers authenticated client connections before delegating to the original
// outbound handler. It intentionally leaves unsupported or incomplete observations untouched.
type leaseTrackedOutbound struct {
	outbound.Handler
	registry *leaseConnectionRegistry
}

// Dispatch intercepts authenticated sessions, then delegates traffic to the original handler.
func (h *leaseTrackedOutbound) Dispatch(ctx context.Context, link *transport.Link) {
	if h == nil || h.Handler == nil {
		return
	}
	inbound := session.InboundFromContext(ctx)
	if inbound != nil && inbound.User != nil && inbound.Conn != nil && h.registry != nil {
		key, ok := leaseKeyFromInbound(inbound)
		if ok {
			release := h.registry.register(key, inbound.Conn)
			defer release()
		}
	}
	h.Handler.Dispatch(ctx, link)
}

// leaseKeyFromInbound converts Xray's authenticated inbound metadata into a canonical lease key.
func leaseKeyFromInbound(inbound *session.Inbound) (leaseConnectionKey, bool) {
	if inbound == nil || inbound.User == nil || strings.TrimSpace(inbound.User.Email) == "" || inbound.Source.Address == nil || !inbound.Source.Address.Family().IsIP() {
		return leaseConnectionKey{}, false
	}
	protocol := leaseProtocol(inbound.Name)
	if protocol == xrayruntimev1.Protocol_PROTOCOL_UNSPECIFIED {
		return leaseConnectionKey{}, false
	}
	address, ok := netip.AddrFromSlice(inbound.Source.Address.IP())
	if !ok || !address.IsValid() {
		return leaseConnectionKey{}, false
	}
	return leaseConnectionKey{protocol: protocol, email: inbound.User.Email, sourceIP: address.Unmap()}, true
}

// leaseProtocol maps Xray inbound implementation names to the product protocol enum.
func leaseProtocol(name string) xrayruntimev1.Protocol {
	switch name {
	case "vless":
		return xrayruntimev1.Protocol_PROTOCOL_VLESS
	case "vmess":
		return xrayruntimev1.Protocol_PROTOCOL_VMESS
	case "hysteria":
		return xrayruntimev1.Protocol_PROTOCOL_HYSTERIA2
	case "trojan":
		return xrayruntimev1.Protocol_PROTOCOL_TROJAN
	case "shadowsocks-2022", "shadowsocks-2022-multi":
		return xrayruntimev1.Protocol_PROTOCOL_SHADOWSOCKS
	default:
		return xrayruntimev1.Protocol_PROTOCOL_UNSPECIFIED
	}
}

// register adds a dispatch reference and returns a function that releases it exactly once.
func (r *leaseConnectionRegistry) register(key leaseConnectionKey, connection interface{ Close() error }) func() {
	identity := connectionIdentity(connection)
	if r == nil || identity == 0 || !key.sourceIP.IsValid() || key.protocol == xrayruntimev1.Protocol_PROTOCOL_UNSPECIFIED || strings.TrimSpace(key.email) == "" {
		return func() {}
	}
	r.mu.Lock()
	if r.closing[key] {
		r.mu.Unlock()
		_ = connection.Close()
		return func() {}
	}
	byConnection := r.connections[key]
	if byConnection == nil {
		byConnection = make(map[uintptr]*leaseConnection)
		r.connections[key] = byConnection
		r.connectedAt[key] = time.Now().UTC()
	}
	tracked := byConnection[identity]
	if tracked == nil {
		tracked = &leaseConnection{connection: connection}
		byConnection[identity] = tracked
	}
	tracked.references++
	r.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() { r.release(key, identity) })
	}
}

// connectionStart returns when the continuous source-IP lease first opened.
func (r *leaseConnectionRegistry) connectionStart(key leaseConnectionKey) (time.Time, bool) {
	if r == nil {
		return time.Time{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	connectedAt := r.connectedAt[key]
	return connectedAt, !connectedAt.IsZero() && len(r.connections[key]) > 0
}

// observations returns the open source-IP leases for one authenticated user.
func (r *leaseConnectionRegistry) observations(protocol xrayruntimev1.Protocol, email string) []RuntimeIPObservation {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var observations []RuntimeIPObservation
	for key, connections := range r.connections {
		if key.protocol != protocol || key.email != email || len(connections) == 0 {
			continue
		}
		observations = append(observations, RuntimeIPObservation{
			Address: key.sourceIP.String(), ConnectedAt: r.connectedAt[key], LastSeen: r.connectedAt[key],
		})
	}
	return observations
}

// release decrements a dispatch reference and removes an inactive physical connection.
func (r *leaseConnectionRegistry) release(key leaseConnectionKey, identity uintptr) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	byConnection := r.connections[key]
	tracked := byConnection[identity]
	if tracked == nil {
		return
	}
	tracked.references--
	if tracked.references <= 0 {
		delete(byConnection, identity)
		if len(byConnection) == 0 {
			delete(r.connections, key)
			delete(r.connectedAt, key)
		}
	}
}

// disconnect closes every currently registered connection for one authenticated lease.
func (r *leaseConnectionRegistry) disconnect(operationID string, key leaseConnectionKey) (int, bool, error) {
	if r == nil {
		return 0, false, errors.New("lease connection registry is unavailable")
	}
	operationID = strings.TrimSpace(operationID)
	if operationID == "" || len(operationID) > 128 {
		return 0, false, errors.New("lease disconnect operation ID is invalid")
	}
	if !key.sourceIP.IsValid() || key.protocol == xrayruntimev1.Protocol_PROTOCOL_UNSPECIFIED || strings.TrimSpace(key.email) == "" {
		return 0, false, errors.New("lease disconnect identity is invalid")
	}
	r.mu.Lock()
	if previous, ok := r.operations[operationID]; ok {
		r.mu.Unlock()
		if previous.key != key {
			return 0, true, errors.New("lease disconnect operation ID was reused for a different lease")
		}
		return previous.closed, true, previous.err
	}
	r.closing[key] = true
	tracked := r.connections[key]
	connections := make([]interface{ Close() error }, 0, len(tracked))
	for _, value := range tracked {
		connections = append(connections, value.connection)
	}
	r.mu.Unlock()

	closed := 0
	var closeErr error
	for _, connection := range connections {
		if err := connection.Close(); err != nil {
			closeErr = errors.Join(closeErr, err)
			continue
		}
		closed++
	}
	r.mu.Lock()
	delete(r.closing, key)
	r.operations[operationID] = leaseDisconnectResult{closed: closed, err: closeErr, key: key}
	r.operationIDs = append(r.operationIDs, operationID)
	if len(r.operationIDs) > leaseOperationLimit {
		oldest := r.operationIDs[0]
		r.operationIDs = r.operationIDs[1:]
		delete(r.operations, oldest)
	}
	r.mu.Unlock()
	return closed, false, closeErr
}

// LeaseDisconnectSupported reports whether this runtime has verified TCP
// connection-close support for the requested protocol.
func (e *Engine) LeaseDisconnectSupported(protocol xrayruntimev1.Protocol) bool {
	if e == nil || !e.leaseTracking {
		return false
	}
	switch protocol {
	case xrayruntimev1.Protocol_PROTOCOL_VLESS,
		xrayruntimev1.Protocol_PROTOCOL_VMESS,
		xrayruntimev1.Protocol_PROTOCOL_TROJAN:
		return true
	default:
		// UDP multiplexing needs protocol-specific close behavior. Do not
		// advertise support for Hysteria 2 or Shadowsocks before those paths
		// have integration coverage proving a single-lease disconnect.
		return false
	}
}

// DisconnectLease closes only the authenticated connection handles currently
// tracked for one protocol, profile and canonical source IP.
func (e *Engine) DisconnectLease(ctx context.Context, protocol xrayruntimev1.Protocol, email, sourceIP, operationID string) (int, bool, error) {
	if e == nil || e.leases == nil {
		return 0, false, errors.New("Xray lease tracking is unavailable")
	}
	if !e.LeaseDisconnectSupported(protocol) {
		return 0, false, errors.New("Xray lease disconnect is not supported for this protocol")
	}
	if err := ctx.Err(); err != nil {
		return 0, false, err
	}
	address, err := netip.ParseAddr(strings.TrimSpace(sourceIP))
	if err != nil {
		return 0, false, errors.New("lease source IP is invalid")
	}
	key := leaseConnectionKey{protocol: protocol, email: strings.TrimSpace(email), sourceIP: address.Unmap()}
	return e.leases.disconnect(operationID, key)
}

// connectionIdentity returns a stable identity for the pointer-backed Xray connection value.
func connectionIdentity(connection any) uintptr {
	if connection == nil {
		return 0
	}
	value := reflect.ValueOf(connection)
	if value.Kind() != reflect.Pointer || value.IsNil() {
		return 0
	}
	return value.Pointer()
}
