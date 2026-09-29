package control

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
)

// Service maps the prototype's gRPC methods onto the AWG lifecycle manager.
type Service struct {
	manager *Manager
	options Options
}

// NewService creates the RPC adapter for a configured lifecycle manager.
func NewService(manager *Manager, options Options) *Service {
	return &Service{manager: manager, options: options}
}

// GetStatus returns the running device identity and its configured listener.
func (s *Service) GetStatus(context.Context, *structpb.Struct) (*structpb.Struct, error) {
	publicKey, peers, err := s.manager.Status()
	if err != nil {
		return nil, mapError(err)
	}
	return response(map[string]any{
		"running":        true,
		"publicKey":      publicKey,
		"listenPort":     float64(s.options.ListenPort),
		"publicHost":     s.options.PublicHost,
		"publicPort":     float64(s.options.PublicPort),
		"peerCount":      float64(peers),
		"ipv4Network":    s.options.IPv4Prefix.String(),
		"ipv6Network":    s.options.IPv6Prefix.String(),
		"protocol":       "AmneziaWG",
		"serviceVersion": "prototype-v1",
	})
}

// ListPeers returns current peer labels, public keys, and allocated tunnel addresses.
func (s *Service) ListPeers(context.Context, *structpb.Struct) (*structpb.Struct, error) {
	peers := s.manager.Peers()
	items := make([]any, 0, len(peers))
	for _, peer := range peers {
		items = append(items, peerMap(peer))
	}
	return response(map[string]any{"peers": items})
}

// AddPeer activates a peer immediately and persists it for process recovery.
func (s *Service) AddPeer(_ context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	name, err := stringField(request, "name")
	if err != nil {
		return nil, err
	}
	publicKey, err := stringField(request, "publicKey")
	if err != nil {
		return nil, err
	}
	peer, err := s.manager.AddPeer(name, publicKey)
	if err != nil {
		return nil, mapError(err)
	}
	return response(peerMap(peer))
}

// RemovePeer revokes the selected peer in the live device and persistent state.
func (s *Service) RemovePeer(_ context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	name, err := stringField(request, "name")
	if err != nil {
		return nil, err
	}
	if err := s.manager.RemovePeer(name); err != nil {
		return nil, mapError(err)
	}
	return response(map[string]any{"removed": true, "name": name})
}

// RenderClientConfig returns a native profile without ever persisting the client private key.
func (s *Service) RenderClientConfig(_ context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	name, err := stringField(request, "name")
	if err != nil {
		return nil, err
	}
	privateKey, err := stringField(request, "privateKey")
	if err != nil {
		return nil, err
	}
	config, err := s.manager.RenderClientConfig(name, privateKey)
	if err != nil {
		return nil, mapError(err)
	}
	return response(map[string]any{"config": config})
}

func peerMap(peer Peer) map[string]any {
	return map[string]any{
		"name": peer.Name, "publicKey": peer.PublicKey, "ipv4": peer.IPv4, "ipv6": peer.IPv6,
		"createdAt": peer.CreatedAt.UTC().Format(time.RFC3339),
	}
}

var _ API = (*Service)(nil)
