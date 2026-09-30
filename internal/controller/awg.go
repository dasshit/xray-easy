package controller

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"time"

	"xray-easy/internal/awgcontrol"
	"xray-easy/internal/domain"

	"google.golang.org/protobuf/types/known/structpb"
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
	response, err := c.controller.call(ctx, "GetAmneziaWGStatus", nil)
	if err != nil {
		return domain.AmneziaWGStatus{}, err
	}
	fields := response.GetFields()
	var value domain.AmneziaWGStatus
	if value.Running, err = responseBool(fields, "running"); err != nil {
		return value, err
	}
	for key, target := range map[string]*string{"public_key": &value.PublicKey, "public_host": &value.PublicHost, "ipv4_network": &value.IPv4Network, "ipv6_network": &value.IPv6Network, "service_version": &value.ServiceVersion} {
		*target, err = responseString(fields, key, false)
		if err != nil {
			return value, err
		}
	}
	for key, target := range map[string]*int{"listen_port": &value.ListenPort, "public_port": &value.PublicPort, "peer_count": &value.PeerCount} {
		*target, err = responseInt(fields, key)
		if err != nil {
			return value, err
		}
	}
	return value, nil
}

func (c *AWGClient) ListPeers(ctx context.Context) ([]domain.AmneziaWGPeer, error) {
	response, err := c.controller.call(ctx, "ListAmneziaWGPeers", nil)
	if err != nil {
		return nil, err
	}
	items, err := listField(response.GetFields(), "peers")
	if err != nil {
		return nil, err
	}
	peers := make([]domain.AmneziaWGPeer, 0, len(items))
	for index, item := range items {
		fields := item.GetStructValue()
		if fields == nil {
			return nil, fmt.Errorf("decode Controller AWG peers: item %d must be an object", index)
		}
		values := fields.GetFields()
		peer, err := parsePeer(values)
		if err != nil {
			return nil, err
		}
		peers = append(peers, peer)
	}
	return peers, nil
}

func (c *AWGClient) CreatePeer(ctx context.Context, name string) (domain.AmneziaWGPeer, error) {
	response, err := c.controller.call(ctx, "CreateAmneziaWGPeer", map[string]any{"name": name})
	if err != nil {
		return domain.AmneziaWGPeer{}, err
	}
	return parsePeer(response.GetFields())
}

func (c *AWGClient) RemovePeer(ctx context.Context, name string) error {
	_, err := c.controller.call(ctx, "RemoveAmneziaWGPeer", map[string]any{"name": name})
	return err
}

func (c *AWGClient) ClientConfig(ctx context.Context, name string) (string, error) {
	response, err := c.controller.call(ctx, "GetAmneziaWGClientConfig", map[string]any{"name": name})
	if err != nil {
		return "", err
	}
	return responseString(response.GetFields(), "config", true)
}

func (c *AWGClient) PeerStats(ctx context.Context) ([]domain.AmneziaWGPeerStats, error) {
	response, err := c.controller.call(ctx, "GetAmneziaWGPeerStats", nil)
	if err != nil {
		return nil, err
	}
	items, err := listField(response.GetFields(), "peers")
	if err != nil {
		return nil, err
	}
	peers := make([]domain.AmneziaWGPeerStats, 0, len(items))
	for index, item := range items {
		fields := item.GetStructValue()
		if fields == nil {
			return nil, fmt.Errorf("decode Controller AWG stats: item %d must be an object", index)
		}
		values := fields.GetFields()
		name, err := responseString(values, "name", true)
		if err != nil {
			return nil, err
		}
		source, err := responseString(values, "source_ip", false)
		if err != nil {
			return nil, err
		}
		lastSeen, err := responseTime(values, "last_seen")
		if err != nil {
			return nil, err
		}
		upload, err := responseCounter(values, "upload_bytes")
		if err != nil {
			return nil, err
		}
		download, err := responseCounter(values, "download_bytes")
		if err != nil {
			return nil, err
		}
		peers = append(peers, domain.AmneziaWGPeerStats{Name: name, SourceIP: source, LastSeen: lastSeen, UploadBytes: upload, DownloadBytes: download})
	}
	return peers, nil
}

func (c *AWGClient) ExportBackup(ctx context.Context) ([]byte, error) {
	response, err := c.controller.call(ctx, "ExportAmneziaWGBackup", nil)
	if err != nil {
		return nil, err
	}
	value, err := responseString(response.GetFields(), "data", true)
	if err != nil {
		return nil, err
	}
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode Controller AWG backup: %w", err)
	}
	return data, nil
}

func (c *AWGClient) RestoreBackup(ctx context.Context, data []byte) error {
	_, err := c.controller.call(ctx, "RestoreAmneziaWGBackup", map[string]any{"data": base64.StdEncoding.EncodeToString(data)})
	return err
}

func parsePeer(fields map[string]*structpb.Value) (domain.AmneziaWGPeer, error) {
	var peer domain.AmneziaWGPeer
	var err error
	if peer.Name, err = responseString(fields, "name", true); err != nil {
		return peer, err
	}
	if peer.PublicKey, err = responseString(fields, "public_key", true); err != nil {
		return peer, err
	}
	if peer.IPv4, err = responseString(fields, "ipv4", true); err != nil {
		return peer, err
	}
	if peer.IPv6, err = responseString(fields, "ipv6", true); err != nil {
		return peer, err
	}
	if peer.CreatedAt, err = responseTime(fields, "created_at"); err != nil {
		return peer, err
	}
	return peer, nil
}

func responseBool(fields map[string]*structpb.Value, key string) (bool, error) {
	value := fields[key]
	if value == nil {
		return false, fmt.Errorf("decode Controller response: missing %s", key)
	}
	boolean, ok := value.GetKind().(*structpb.Value_BoolValue)
	if !ok {
		return false, fmt.Errorf("decode Controller response: %s must be a boolean", key)
	}
	return boolean.BoolValue, nil
}

func listField(fields map[string]*structpb.Value, key string) ([]*structpb.Value, error) {
	value := fields[key]
	if value == nil || value.GetListValue() == nil {
		return nil, fmt.Errorf("decode Controller response: %s must be a list", key)
	}
	return value.GetListValue().GetValues(), nil
}

func responseCounter(fields map[string]*structpb.Value, key string) (int64, error) {
	value, err := responseString(fields, key, true)
	if err != nil {
		return 0, err
	}
	counter, err := strconv.ParseInt(value, 10, 64)
	if err != nil || counter < 0 {
		return 0, fmt.Errorf("decode Controller response: %s must be a non-negative integer", key)
	}
	return counter, nil
}

func responseTime(fields map[string]*structpb.Value, key string) (time.Time, error) {
	value, err := responseString(fields, key, false)
	if err != nil {
		return time.Time{}, err
	}
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("decode Controller response: %s must be RFC3339", key)
	}
	return parsed, nil
}

var _ awgcontrol.Gateway = (*AWGClient)(nil)
var _ interface {
	PeerStats(context.Context) ([]domain.AmneziaWGPeerStats, error)
	ExportBackup(context.Context) ([]byte, error)
	RestoreBackup(context.Context, []byte) error
} = (*AWGClient)(nil)
