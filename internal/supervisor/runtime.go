package supervisor

import (
	"context"
	"fmt"

	supervisorv1 "xray-easy/internal/supervisor/api/v1"
	"xray-easy/internal/xrayapi"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

// AddProtocolUser adds one protocol-specific identity to a live Xray inbound.
func (c *Client) AddProtocolUser(ctx context.Context, protocol, email, id, flow string) error {
	protocolValue, err := xrayProtocolValue(protocol)
	if err != nil {
		return err
	}
	request := &supervisorv1.AlterUserRequest{Action: supervisorv1.XrayUserAction_XRAY_USER_ACTION_ADD, Protocol: protocolValue, Email: email, Id: id, Flow: flow}
	_, err = c.call(ctx, supervisorv1.Supervisor_AlterUser_FullMethodName, request,
		func(ctx context.Context) (proto.Message, error) { return c.rpc.AlterUser(ctx, request) })
	return err
}

// RemoveProtocolUser removes one protocol-specific identity from a live Xray inbound.
func (c *Client) RemoveProtocolUser(ctx context.Context, protocol, email string) error {
	protocolValue, err := xrayProtocolValue(protocol)
	if err != nil {
		return err
	}
	request := &supervisorv1.AlterUserRequest{Action: supervisorv1.XrayUserAction_XRAY_USER_ACTION_REMOVE, Protocol: protocolValue, Email: email}
	_, err = c.call(ctx, supervisorv1.Supervisor_AlterUser_FullMethodName, request,
		func(ctx context.Context) (proto.Message, error) { return c.rpc.AlterUser(ctx, request) })
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
	protocol, ok := map[string]string{"vless-reality": "vless", "hysteria2": "hysteria2", "vmess-tls": "vmess"}[inbound]
	if !ok {
		return nil, fmt.Errorf("unsupported Xray inbound %q", inbound)
	}
	protocolValue, _ := xrayProtocolValue(protocol)
	request := &supervisorv1.ListUsersRequest{Protocol: protocolValue}
	result, err := c.call(ctx, supervisorv1.Supervisor_ListUsers_FullMethodName, request,
		func(ctx context.Context) (proto.Message, error) { return c.rpc.ListUsers(ctx, request) })
	if err != nil {
		return nil, err
	}
	return append([]string(nil), result.(*supervisorv1.ListUsersResponse).Users...), nil
}

// Poll reads per-user Xray counters and source IP observations.
func (c *Client) Poll(ctx context.Context) ([]xrayapi.UserStats, error) {
	result, err := c.call(ctx, supervisorv1.Supervisor_GetUserStats_FullMethodName, new(emptypb.Empty),
		func(ctx context.Context) (proto.Message, error) { return c.rpc.GetUserStats(ctx, new(emptypb.Empty)) })
	if err != nil {
		return nil, err
	}
	response := result.(*supervisorv1.UserStatsResponse)
	users := make([]xrayapi.UserStats, 0, len(response.Users))
	for index, item := range response.Users {
		if item == nil || item.Email == "" || item.UploadBytes < 0 || item.DownloadBytes < 0 {
			return nil, fmt.Errorf("decode supervisor user stats: item %d has invalid fields", index)
		}
		lastSeen, err := protobufTimeToTime("last_seen", item.LastSeen)
		if err != nil {
			return nil, err
		}
		user := xrayapi.UserStats{Email: item.Email, UploadBytes: item.UploadBytes, DownloadBytes: item.DownloadBytes, LastSeen: lastSeen}
		user.SourceIPs = make([]xrayapi.IPObservation, 0, len(item.SourceIps))
		for ipIndex, address := range item.SourceIps {
			if address == nil || address.Address == "" {
				return nil, fmt.Errorf("decode supervisor user stats: source IP %d for user %q is invalid", ipIndex, item.Email)
			}
			ipLastSeen, err := protobufTimeToTime("source_ips.last_seen", address.LastSeen)
			if err != nil {
				return nil, err
			}
			user.SourceIPs = append(user.SourceIPs, xrayapi.IPObservation{Address: address.Address, LastSeen: ipLastSeen})
		}
		users = append(users, user)
	}
	return users, nil
}

func xrayProtocolValue(protocol string) (supervisorv1.XrayProtocol, error) {
	switch protocol {
	case "vless":
		return supervisorv1.XrayProtocol_XRAY_PROTOCOL_VLESS, nil
	case "vmess":
		return supervisorv1.XrayProtocol_XRAY_PROTOCOL_VMESS, nil
	case "hysteria2":
		return supervisorv1.XrayProtocol_XRAY_PROTOCOL_HYSTERIA2, nil
	default:
		return supervisorv1.XrayProtocol_XRAY_PROTOCOL_UNSPECIFIED, fmt.Errorf("unsupported Xray protocol %q", protocol)
	}
}
