package supervisor

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"xray-easy/internal/xrayapi"

	"google.golang.org/protobuf/types/known/structpb"
)

// AddProtocolUser adds one protocol-specific identity to a live Xray inbound.
func (c *Client) AddProtocolUser(ctx context.Context, protocol, email, id, flow string) error {
	_, err := c.call(ctx, "AlterUser", stringRequest(map[string]string{
		"action": "add", "protocol": protocol, "email": email, "id": id, "flow": flow,
	}))
	return err
}

// RemoveProtocolUser removes a protocol-specific identity from a live Xray inbound.
func (c *Client) RemoveProtocolUser(ctx context.Context, protocol, email string) error {
	_, err := c.call(ctx, "AlterUser", stringRequest(map[string]string{
		"action": "remove", "protocol": protocol, "email": email,
	}))
	return err
}

// AddUser adds a VLESS identity to the live inbound.
func (c *Client) AddUser(ctx context.Context, email, id, flow string) error {
	return c.AddProtocolUser(ctx, "vless", email, id, flow)
}

// RemoveUser removes a VLESS identity from the live inbound.
func (c *Client) RemoveUser(ctx context.Context, email string) error {
	return c.RemoveProtocolUser(ctx, "vless", email)
}

// AddHysteriaUser adds a Hysteria 2 credential to the configured inbound.
func (c *Client) AddHysteriaUser(ctx context.Context, email, password string) error {
	return c.AddProtocolUser(ctx, "hysteria2", email, password, "")
}

// RemoveHysteriaUser removes a Hysteria 2 credential from the configured inbound.
func (c *Client) RemoveHysteriaUser(ctx context.Context, email string) error {
	return c.RemoveProtocolUser(ctx, "hysteria2", email)
}

// AddVMessUser adds a VMess UUID to the configured inbound.
func (c *Client) AddVMessUser(ctx context.Context, email, id string) error {
	return c.AddProtocolUser(ctx, "vmess", email, id, "")
}

// RemoveVMessUser removes a VMess user from the configured inbound.
func (c *Client) RemoveVMessUser(ctx context.Context, email string) error {
	return c.RemoveProtocolUser(ctx, "vmess", email)
}

// Users returns the currently loaded VLESS identities.
func (c *Client) Users(ctx context.Context) ([]string, error) {
	return c.UsersInInbound(ctx, "vless-reality")
}

// UsersInInbound returns loaded users for a supported Xray inbound tag.
func (c *Client) UsersInInbound(ctx context.Context, inbound string) ([]string, error) {
	protocol := map[string]string{"vless-reality": "vless", "hysteria2": "hysteria2", "vmess-tls": "vmess"}[inbound]
	if protocol == "" {
		return nil, fmt.Errorf("unsupported Xray inbound %q", inbound)
	}
	response, err := c.call(ctx, "ListUsers", stringRequest(map[string]string{"protocol": protocol}))
	if err != nil {
		return nil, err
	}
	value := response.GetFields()["users"]
	if value == nil || value.GetListValue() == nil {
		return nil, fmt.Errorf("decode supervisor users: users must be a list")
	}
	users := make([]string, 0, len(value.GetListValue().GetValues()))
	for index, item := range value.GetListValue().GetValues() {
		if _, ok := item.GetKind().(*structpb.Value_StringValue); !ok {
			return nil, fmt.Errorf("decode supervisor users: item %d must be a string", index)
		}
		users = append(users, item.GetStringValue())
	}
	return users, nil
}

// Poll reads per-user Xray counters and source IP observations.
func (c *Client) Poll(ctx context.Context) ([]xrayapi.UserStats, error) {
	response, err := c.call(ctx, "GetUserStats", new(structpb.Struct))
	if err != nil {
		return nil, err
	}
	items := response.GetFields()["users"]
	if items == nil || items.GetListValue() == nil {
		return nil, fmt.Errorf("decode supervisor user stats: users must be a list")
	}
	users := make([]xrayapi.UserStats, 0, len(items.GetListValue().GetValues()))
	for index, item := range items.GetListValue().GetValues() {
		fields := item.GetStructValue()
		if fields == nil {
			return nil, fmt.Errorf("decode supervisor user stats: item %d must be an object", index)
		}
		values := fields.GetFields()
		user := xrayapi.UserStats{}
		if user.Email, err = responseString(values, "email", true); err != nil {
			return nil, err
		}
		if user.UploadBytes, err = responseCounter(values, "upload_bytes"); err != nil {
			return nil, err
		}
		if user.DownloadBytes, err = responseCounter(values, "download_bytes"); err != nil {
			return nil, err
		}
		if user.LastSeen, err = responseTime(values, "last_seen"); err != nil {
			return nil, err
		}
		ips := values["source_ips"]
		if ips == nil || ips.GetListValue() == nil {
			return nil, fmt.Errorf("decode supervisor user stats: source_ips must be a list")
		}
		user.SourceIPs = make([]xrayapi.IPObservation, 0, len(ips.GetListValue().GetValues()))
		for ipIndex, ip := range ips.GetListValue().GetValues() {
			ipFields := ip.GetStructValue()
			if ipFields == nil {
				return nil, fmt.Errorf("decode supervisor user stats: source IP %d must be an object", ipIndex)
			}
			address, err := responseString(ipFields.GetFields(), "address", true)
			if err != nil {
				return nil, err
			}
			lastSeen, err := responseTime(ipFields.GetFields(), "last_seen")
			if err != nil {
				return nil, err
			}
			user.SourceIPs = append(user.SourceIPs, xrayapi.IPObservation{Address: address, LastSeen: lastSeen})
		}
		users = append(users, user)
	}
	return users, nil
}

func responseCounter(fields map[string]*structpb.Value, key string) (int64, error) {
	value, err := responseString(fields, key, true)
	if err != nil {
		return 0, err
	}
	counter, err := strconv.ParseInt(value, 10, 64)
	if err != nil || counter < 0 {
		return 0, fmt.Errorf("decode supervisor response: %s must be a non-negative integer", key)
	}
	return counter, nil
}

func responseTime(fields map[string]*structpb.Value, key string) (time.Time, error) {
	value, err := responseString(fields, key, false)
	if err != nil || value == "" {
		return time.Time{}, err
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("decode supervisor response: %s must be an RFC3339 timestamp", key)
	}
	return parsed, nil
}
