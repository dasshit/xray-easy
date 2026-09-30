package main

import (
	"context"
	"strconv"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func (s *supervisor) AlterUser(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	if err := rpcFields(request, "action", "protocol", "email", "id", "flow"); err != nil {
		return nil, err
	}
	action, err := rpcString(request, "action", true)
	if err != nil {
		return nil, err
	}
	protocol, err := rpcString(request, "protocol", true)
	if err != nil {
		return nil, err
	}
	email, err := rpcString(request, "email", true)
	if err != nil {
		return nil, err
	}
	id, err := rpcString(request, "id", action == "add")
	if err != nil {
		return nil, err
	}
	flow, err := rpcString(request, "flow", false)
	if err != nil {
		return nil, err
	}
	if s.handler == nil {
		return nil, status.Error(codes.Unavailable, "Xray Handler adapter is unavailable")
	}
	switch action {
	case "add":
		switch protocol {
		case "vless":
			err = s.handler.AddUser(ctx, email, id, flow)
		case "vmess":
			err = s.handler.AddVMessUser(ctx, email, id)
		case "hysteria2":
			err = s.handler.AddHysteriaUser(ctx, email, id)
		default:
			return nil, status.Error(codes.InvalidArgument, "unsupported Xray protocol")
		}
	case "remove":
		if id != "" || flow != "" {
			return nil, status.Error(codes.InvalidArgument, "remove operation cannot include credentials")
		}
		switch protocol {
		case "vless":
			err = s.handler.RemoveUser(ctx, email)
		case "vmess":
			err = s.handler.RemoveVMessUser(ctx, email)
		case "hysteria2":
			err = s.handler.RemoveHysteriaUser(ctx, email)
		default:
			return nil, status.Error(codes.InvalidArgument, "unsupported Xray protocol")
		}
	default:
		return nil, status.Error(codes.InvalidArgument, "action must be add or remove")
	}
	if err != nil {
		return nil, rpcOperationError(codes.FailedPrecondition, err)
	}
	return rpcResponse(map[string]any{"ok": true})
}

func (s *supervisor) ListUsers(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	if err := rpcFields(request, "protocol"); err != nil {
		return nil, err
	}
	protocol, err := rpcString(request, "protocol", true)
	if err != nil {
		return nil, err
	}
	if s.handler == nil {
		return nil, status.Error(codes.Unavailable, "Xray Handler adapter is unavailable")
	}
	var users []string
	switch protocol {
	case "vless":
		users, err = s.handler.Users(ctx)
	case "vmess":
		users, err = s.handler.UsersInInbound(ctx, "vmess-tls")
	case "hysteria2":
		users, err = s.handler.UsersInInbound(ctx, "hysteria2")
	default:
		return nil, status.Error(codes.InvalidArgument, "unsupported Xray protocol")
	}
	if err != nil {
		return nil, rpcOperationError(codes.Unavailable, err)
	}
	values := make([]any, len(users))
	for index, user := range users {
		values[index] = user
	}
	return rpcResponse(map[string]any{"users": values})
}

func (s *supervisor) GetUserStats(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	if err := rpcFields(request); err != nil {
		return nil, err
	}
	if s.stats == nil {
		return nil, status.Error(codes.Unavailable, "Xray statistics adapter is unavailable")
	}
	users, err := s.stats.Poll(ctx)
	if err != nil {
		return nil, rpcOperationError(codes.Unavailable, err)
	}
	items := make([]any, 0, len(users))
	for _, user := range users {
		ips := make([]any, 0, len(user.SourceIPs))
		for _, address := range user.SourceIPs {
			ips = append(ips, map[string]any{"address": address.Address, "last_seen": runtimeTime(address.LastSeen)})
		}
		items = append(items, map[string]any{
			"email": user.Email, "upload_bytes": strconv.FormatInt(user.UploadBytes, 10),
			"download_bytes": strconv.FormatInt(user.DownloadBytes, 10), "last_seen": runtimeTime(user.LastSeen), "source_ips": ips,
		})
	}
	return rpcResponse(map[string]any{"users": items})
}

func runtimeTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
