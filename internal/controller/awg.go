package controller

import (
	"context"
	"fmt"

	"xray-easy/internal/awgcontrol"
	"xray-easy/internal/controller/api/v1"
	"xray-easy/internal/domain"
)

// AWGClient exposes the AmneziaWG subset through the shared Controller gRPC
// connection. It never owns a separate network connection.
type AWGClient struct{ controller *Client }

// AWG returns the AmneziaWG adapter view of this Controller client.
func (c *Client) AWG() *AWGClient { return &AWGClient{controller: c} }

// Close closes the shared Controller connection.
func (c *AWGClient) Close() error {
	if c == nil || c.controller == nil {
		return nil
	}
	return c.controller.Close()
}

func (c *AWGClient) Status(ctx context.Context) (domain.AmneziaWGStatus, error) {
	response, err := c.controller.call(ctx, "GetAmneziaWGStatus", &controllerv1.EmptyRequest{})
	if err != nil {
		return domain.AmneziaWGStatus{}, err
	}
	value := response.(*controllerv1.AmneziaWGStatusResponse)
	if value.ListenPort < 0 || value.ListenPort > 65535 || value.PublicPort < 0 || value.PublicPort > 65535 || value.PeerCount < 0 {
		return domain.AmneziaWGStatus{}, fmt.Errorf("decode Controller AmneziaWG status: numeric field out of range")
	}
	return domain.AmneziaWGStatus{Running: value.Running, PublicKey: value.PublicKey, ListenPort: int(value.ListenPort), PublicHost: value.PublicHost, PublicPort: int(value.PublicPort), PeerCount: int(value.PeerCount), IPv4Network: value.Ipv4Network, IPv6Network: value.Ipv6Network, ServiceVersion: value.ServiceVersion}, nil
}

func (c *AWGClient) ListPeers(ctx context.Context) ([]domain.AmneziaWGPeer, error) {
	response, err := c.controller.call(ctx, "ListAmneziaWGPeers", &controllerv1.EmptyRequest{})
	if err != nil {
		return nil, err
	}
	items := response.(*controllerv1.ListAmneziaWGPeersResponse).Peers
	peers := make([]domain.AmneziaWGPeer, 0, len(items))
	for index, item := range items {
		peer, err := fromProtoPeer(item)
		if err != nil {
			return nil, fmt.Errorf("decode Controller AWG peer %d: %w", index, err)
		}
		peers = append(peers, peer)
	}
	return peers, nil
}

func (c *AWGClient) CreatePeer(ctx context.Context, name string) (domain.AmneziaWGPeer, error) {
	response, err := c.controller.call(ctx, "CreateAmneziaWGPeer", &controllerv1.CreateAmneziaWGPeerRequest{Name: name})
	if err != nil {
		return domain.AmneziaWGPeer{}, err
	}
	return fromProtoPeer(response.(*controllerv1.AmneziaWGPeer))
}

func (c *AWGClient) RemovePeer(ctx context.Context, name string) error {
	_, err := c.controller.call(ctx, "RemoveAmneziaWGPeer", &controllerv1.RemoveAmneziaWGPeerRequest{Name: name})
	return err
}

func (c *AWGClient) ClientConfig(ctx context.Context, name string) (string, error) {
	response, err := c.controller.call(ctx, "GetAmneziaWGClientConfig", &controllerv1.GetAmneziaWGClientConfigRequest{Name: name})
	if err != nil {
		return "", err
	}
	return response.(*controllerv1.AmneziaWGClientConfigResponse).Config, nil
}

func (c *AWGClient) PeerStats(ctx context.Context) ([]domain.AmneziaWGPeerStats, error) {
	response, err := c.controller.call(ctx, "GetAmneziaWGPeerStats", &controllerv1.EmptyRequest{})
	if err != nil {
		return nil, err
	}
	items := response.(*controllerv1.AmneziaWGPeerStatsResponse).Peers
	peers := make([]domain.AmneziaWGPeerStats, 0, len(items))
	for index, item := range items {
		if item == nil || item.Name == "" || item.UploadBytes < 0 || item.DownloadBytes < 0 {
			return nil, fmt.Errorf("decode Controller AWG stats: peer %d has invalid fields", index)
		}
		lastSeen, err := protobufTimeToTime("last_seen", item.LastSeen)
		if err != nil {
			return nil, err
		}
		peers = append(peers, domain.AmneziaWGPeerStats{Name: item.Name, SourceIP: item.SourceIp, LastSeen: lastSeen, UploadBytes: item.UploadBytes, DownloadBytes: item.DownloadBytes})
	}
	return peers, nil
}

func (c *AWGClient) ExportBackup(ctx context.Context) ([]byte, error) {
	response, err := c.controller.call(ctx, "ExportAmneziaWGBackup", &controllerv1.EmptyRequest{})
	if err != nil {
		return nil, err
	}
	return append([]byte{}, response.(*controllerv1.AmneziaWGBackupResponse).Data...), nil
}

func (c *AWGClient) RestoreBackup(ctx context.Context, data []byte) error {
	_, err := c.controller.call(ctx, "RestoreAmneziaWGBackup", &controllerv1.RestoreAmneziaWGBackupRequest{Data: data})
	return err
}

func fromProtoPeer(value *controllerv1.AmneziaWGPeer) (domain.AmneziaWGPeer, error) {
	if value == nil || value.Name == "" || value.PublicKey == "" || value.Ipv4 == "" || value.Ipv6 == "" {
		return domain.AmneziaWGPeer{}, fmt.Errorf("required peer field is empty")
	}
	createdAt, err := protobufTimeToTime("created_at", value.CreatedAt)
	if err != nil {
		return domain.AmneziaWGPeer{}, err
	}
	return domain.AmneziaWGPeer{Name: value.Name, PublicKey: value.PublicKey, IPv4: value.Ipv4, IPv6: value.Ipv6, CreatedAt: createdAt}, nil
}

var _ awgcontrol.Gateway = (*AWGClient)(nil)
var _ interface {
	PeerStats(context.Context) ([]domain.AmneziaWGPeerStats, error)
	ExportBackup(context.Context) ([]byte, error)
	RestoreBackup(context.Context, []byte) error
} = (*AWGClient)(nil)
