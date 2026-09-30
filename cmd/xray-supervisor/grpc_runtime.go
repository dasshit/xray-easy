package main

import (
	"context"
	"time"

	supervisorv1 "xray-easy/internal/supervisor/api/v1"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *supervisor) AlterUser(ctx context.Context, request *supervisorv1.AlterUserRequest) (*supervisorv1.OperationResponse, error) {
	if request == nil || request.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}
	protocol, ok := xrayProtocolName(request.Protocol)
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "unsupported Xray protocol")
	}
	if s.handler == nil {
		return nil, status.Error(codes.Unavailable, "Xray Handler adapter is unavailable")
	}
	var err error
	switch request.Action {
	case supervisorv1.XrayUserAction_XRAY_USER_ACTION_ADD:
		if request.Id == "" {
			return nil, status.Error(codes.InvalidArgument, "id is required for add operation")
		}
		switch protocol {
		case "vless":
			err = s.handler.AddUser(ctx, request.Email, request.Id, request.Flow)
		case "vmess":
			err = s.handler.AddVMessUser(ctx, request.Email, request.Id)
		case "hysteria2":
			err = s.handler.AddHysteriaUser(ctx, request.Email, request.Id)
		}
	case supervisorv1.XrayUserAction_XRAY_USER_ACTION_REMOVE:
		if request.Id != "" || request.Flow != "" {
			return nil, status.Error(codes.InvalidArgument, "remove operation cannot include credentials")
		}
		switch protocol {
		case "vless":
			err = s.handler.RemoveUser(ctx, request.Email)
		case "vmess":
			err = s.handler.RemoveVMessUser(ctx, request.Email)
		case "hysteria2":
			err = s.handler.RemoveHysteriaUser(ctx, request.Email)
		}
	default:
		return nil, status.Error(codes.InvalidArgument, "action must be add or remove")
	}
	if err != nil {
		return nil, rpcOperationError(codes.FailedPrecondition, err)
	}
	return &supervisorv1.OperationResponse{Ok: true, Protocol: protocolVersion}, nil
}

func (s *supervisor) ListUsers(ctx context.Context, request *supervisorv1.ListUsersRequest) (*supervisorv1.ListUsersResponse, error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "protocol is required")
	}
	protocol, ok := xrayProtocolName(request.Protocol)
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "unsupported Xray protocol")
	}
	if s.handler == nil {
		return nil, status.Error(codes.Unavailable, "Xray Handler adapter is unavailable")
	}
	var users []string
	var err error
	switch protocol {
	case "vless":
		users, err = s.handler.Users(ctx)
	case "vmess":
		users, err = s.handler.UsersInInbound(ctx, "vmess-tls")
	case "hysteria2":
		users, err = s.handler.UsersInInbound(ctx, "hysteria2")
	}
	if err != nil {
		return nil, rpcOperationError(codes.Unavailable, err)
	}
	return &supervisorv1.ListUsersResponse{Users: users}, nil
}

func (s *supervisor) GetUserStats(ctx context.Context, _ *emptypb.Empty) (*supervisorv1.UserStatsResponse, error) {
	if s.stats == nil {
		return nil, status.Error(codes.Unavailable, "Xray statistics adapter is unavailable")
	}
	users, err := s.stats.Poll(ctx)
	if err != nil {
		return nil, rpcOperationError(codes.Unavailable, err)
	}
	response := &supervisorv1.UserStatsResponse{Users: make([]*supervisorv1.XrayUserStats, 0, len(users))}
	for _, user := range users {
		item := &supervisorv1.XrayUserStats{
			Email: user.Email, UploadBytes: user.UploadBytes, DownloadBytes: user.DownloadBytes,
			LastSeen:  runtimeTimestamp(user.LastSeen),
			SourceIps: make([]*supervisorv1.SourceIPObservation, 0, len(user.SourceIPs)),
		}
		for _, address := range user.SourceIPs {
			item.SourceIps = append(item.SourceIps, &supervisorv1.SourceIPObservation{Address: address.Address, LastSeen: runtimeTimestamp(address.LastSeen)})
		}
		response.Users = append(response.Users, item)
	}
	return response, nil
}

func xrayProtocolName(value supervisorv1.XrayProtocol) (string, bool) {
	switch value {
	case supervisorv1.XrayProtocol_XRAY_PROTOCOL_VLESS:
		return "vless", true
	case supervisorv1.XrayProtocol_XRAY_PROTOCOL_VMESS:
		return "vmess", true
	case supervisorv1.XrayProtocol_XRAY_PROTOCOL_HYSTERIA2:
		return "hysteria2", true
	default:
		return "", false
	}
}

func runtimeTimestamp(value time.Time) *timestamppb.Timestamp {
	if value.IsZero() {
		return nil
	}
	return timestamppb.New(value.UTC())
}
