package main

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	supervisorv1 "xray-easy/internal/supervisor/api/v1"
	"xray-easy/internal/xrayapi"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type runtimeHandlerStub struct {
	calls []string
	users []string
	err   error
}

func (s *runtimeHandlerStub) AddUser(context.Context, string, string, string) error {
	s.calls = append(s.calls, "add-vless")
	return s.err
}
func (s *runtimeHandlerStub) RemoveUser(context.Context, string) error {
	s.calls = append(s.calls, "remove-vless")
	return s.err
}
func (s *runtimeHandlerStub) Users(context.Context) ([]string, error) {
	s.calls = append(s.calls, "list-vless")
	return s.users, s.err
}
func (s *runtimeHandlerStub) AddHysteriaUser(context.Context, string, string) error {
	s.calls = append(s.calls, "add-hysteria2")
	return s.err
}
func (s *runtimeHandlerStub) RemoveHysteriaUser(context.Context, string) error {
	s.calls = append(s.calls, "remove-hysteria2")
	return s.err
}
func (s *runtimeHandlerStub) AddVMessUser(context.Context, string, string) error {
	s.calls = append(s.calls, "add-vmess")
	return s.err
}
func (s *runtimeHandlerStub) RemoveVMessUser(context.Context, string) error {
	s.calls = append(s.calls, "remove-vmess")
	return s.err
}
func (s *runtimeHandlerStub) UsersInInbound(_ context.Context, tag string) ([]string, error) {
	s.calls = append(s.calls, "list-"+tag)
	return s.users, s.err
}

type runtimeStatsStub struct {
	users []xrayapi.UserStats
	err   error
}

func (s runtimeStatsStub) Poll(context.Context) ([]xrayapi.UserStats, error) { return s.users, s.err }

func TestAlterUserRoutesSupportedProtocolsAndRejectsInvalidRequests(t *testing.T) {
	handler := &runtimeHandlerStub{}
	instance := &supervisor{handler: handler}
	for _, test := range []struct {
		name     string
		request  *supervisorv1.AlterUserRequest
		wantCall string
	}{
		{"add vless", &supervisorv1.AlterUserRequest{Action: supervisorv1.XrayUserAction_XRAY_USER_ACTION_ADD, Protocol: supervisorv1.XrayProtocol_XRAY_PROTOCOL_VLESS, Email: "v@example.test", Id: "uuid", Flow: "xtls-rprx-vision"}, "add-vless"},
		{"add vmess", &supervisorv1.AlterUserRequest{Action: supervisorv1.XrayUserAction_XRAY_USER_ACTION_ADD, Protocol: supervisorv1.XrayProtocol_XRAY_PROTOCOL_VMESS, Email: "m@example.test", Id: "uuid"}, "add-vmess"},
		{"add hysteria", &supervisorv1.AlterUserRequest{Action: supervisorv1.XrayUserAction_XRAY_USER_ACTION_ADD, Protocol: supervisorv1.XrayProtocol_XRAY_PROTOCOL_HYSTERIA2, Email: "h@example.test", Id: "password"}, "add-hysteria2"},
		{"remove vless", &supervisorv1.AlterUserRequest{Action: supervisorv1.XrayUserAction_XRAY_USER_ACTION_REMOVE, Protocol: supervisorv1.XrayProtocol_XRAY_PROTOCOL_VLESS, Email: "v@example.test"}, "remove-vless"},
		{"remove vmess", &supervisorv1.AlterUserRequest{Action: supervisorv1.XrayUserAction_XRAY_USER_ACTION_REMOVE, Protocol: supervisorv1.XrayProtocol_XRAY_PROTOCOL_VMESS, Email: "m@example.test"}, "remove-vmess"},
		{"remove hysteria", &supervisorv1.AlterUserRequest{Action: supervisorv1.XrayUserAction_XRAY_USER_ACTION_REMOVE, Protocol: supervisorv1.XrayProtocol_XRAY_PROTOCOL_HYSTERIA2, Email: "h@example.test"}, "remove-hysteria2"},
	} {
		t.Run(test.name, func(t *testing.T) {
			response, err := instance.AlterUser(context.Background(), test.request)
			if err != nil || !response.GetOk() {
				t.Fatalf("AlterUser() = %v, %v", response, err)
			}
			if handler.calls[len(handler.calls)-1] != test.wantCall {
				t.Fatalf("handler call = %q, want %q", handler.calls[len(handler.calls)-1], test.wantCall)
			}
		})
	}
	for _, request := range []*supervisorv1.AlterUserRequest{
		nil,
		{Action: supervisorv1.XrayUserAction_XRAY_USER_ACTION_ADD, Protocol: supervisorv1.XrayProtocol_XRAY_PROTOCOL_VLESS, Email: "email"},
		{Action: supervisorv1.XrayUserAction_XRAY_USER_ACTION_REMOVE, Protocol: supervisorv1.XrayProtocol_XRAY_PROTOCOL_VLESS, Email: "email", Id: "credential"},
		{Action: supervisorv1.XrayUserAction_XRAY_USER_ACTION_REMOVE, Protocol: supervisorv1.XrayProtocol_XRAY_PROTOCOL_VLESS, Email: "email", Flow: "vision"},
		{Action: supervisorv1.XrayUserAction_XRAY_USER_ACTION_UNSPECIFIED, Protocol: supervisorv1.XrayProtocol_XRAY_PROTOCOL_VLESS, Email: "email"},
		{Action: supervisorv1.XrayUserAction_XRAY_USER_ACTION_ADD, Protocol: supervisorv1.XrayProtocol_XRAY_PROTOCOL_UNSPECIFIED, Email: "email", Id: "id"},
	} {
		if _, err := instance.AlterUser(context.Background(), request); status.Code(err) != codes.InvalidArgument {
			t.Errorf("AlterUser(%+v) error = %v, want InvalidArgument", request, err)
		}
	}
	if _, err := (&supervisor{}).AlterUser(context.Background(), &supervisorv1.AlterUserRequest{Action: supervisorv1.XrayUserAction_XRAY_USER_ACTION_ADD, Protocol: supervisorv1.XrayProtocol_XRAY_PROTOCOL_VLESS, Email: "email", Id: "id"}); status.Code(err) != codes.Unavailable {
		t.Fatalf("missing Handler adapter error = %v", err)
	}
	handler.err = errors.New("runtime failure")
	if _, err := instance.AlterUser(context.Background(), &supervisorv1.AlterUserRequest{Action: supervisorv1.XrayUserAction_XRAY_USER_ACTION_ADD, Protocol: supervisorv1.XrayProtocol_XRAY_PROTOCOL_VLESS, Email: "email", Id: "id"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("Handler failure error = %v", err)
	}
	if _, err := instance.AlterUser(context.Background(), &supervisorv1.AlterUserRequest{Action: supervisorv1.XrayUserAction_XRAY_USER_ACTION_REMOVE, Protocol: supervisorv1.XrayProtocol_XRAY_PROTOCOL_VLESS, Email: "email"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("Handler remove failure error = %v", err)
	}
}

func TestListUsersRoutesAndHandlesUnavailableRuntime(t *testing.T) {
	handler := &runtimeHandlerStub{users: []string{"one@example.test"}}
	instance := &supervisor{handler: handler}
	for protocol, wantCall := range map[supervisorv1.XrayProtocol]string{
		supervisorv1.XrayProtocol_XRAY_PROTOCOL_VLESS:     "list-vless",
		supervisorv1.XrayProtocol_XRAY_PROTOCOL_VMESS:     "list-vmess-tls",
		supervisorv1.XrayProtocol_XRAY_PROTOCOL_HYSTERIA2: "list-hysteria2",
	} {
		response, err := instance.ListUsers(context.Background(), &supervisorv1.ListUsersRequest{Protocol: protocol})
		if err != nil || !reflect.DeepEqual(response.GetUsers(), []string{"one@example.test"}) {
			t.Fatalf("ListUsers(%s) = %v, %v", protocol, response, err)
		}
		if handler.calls[len(handler.calls)-1] != wantCall {
			t.Fatalf("call = %q, want %q", handler.calls[len(handler.calls)-1], wantCall)
		}
	}
	for _, request := range []*supervisorv1.ListUsersRequest{nil, {}, {Protocol: supervisorv1.XrayProtocol_XRAY_PROTOCOL_UNSPECIFIED}} {
		if _, err := instance.ListUsers(context.Background(), request); status.Code(err) != codes.InvalidArgument {
			t.Errorf("ListUsers(%+v) error = %v", request, err)
		}
	}
	if _, err := (&supervisor{}).ListUsers(context.Background(), &supervisorv1.ListUsersRequest{Protocol: supervisorv1.XrayProtocol_XRAY_PROTOCOL_VLESS}); status.Code(err) != codes.Unavailable {
		t.Fatalf("missing Handler error = %v", err)
	}
	handler.err = errors.New("upstream unavailable")
	if _, err := instance.ListUsers(context.Background(), &supervisorv1.ListUsersRequest{Protocol: supervisorv1.XrayProtocol_XRAY_PROTOCOL_VLESS}); status.Code(err) != codes.Unavailable {
		t.Fatalf("Handler error = %v", err)
	}
}

func TestGetUserStatsReturnsTypedPrecisionPreservingTelemetry(t *testing.T) {
	lastSeen := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	instance := &supervisor{stats: runtimeStatsStub{users: []xrayapi.UserStats{{
		Email: "device@example.test", UploadBytes: 9007199254740993, DownloadBytes: 456, LastSeen: lastSeen,
		SourceIPs: []xrayapi.IPObservation{{Address: "203.0.113.2", LastSeen: lastSeen}},
	}}}}
	response, err := instance.GetUserStats(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	user := response.GetUsers()[0]
	if user.UploadBytes != 9007199254740993 || user.DownloadBytes != 456 || !user.LastSeen.AsTime().Equal(lastSeen) {
		t.Fatalf("stats response = %+v", user)
	}
	ip := user.GetSourceIps()[0]
	if ip.Address != "203.0.113.2" || !ip.LastSeen.AsTime().Equal(lastSeen) {
		t.Fatalf("source IP response = %+v", ip)
	}
	if runtimeTimestamp(time.Time{}) != nil {
		t.Fatal("zero timestamps should be omitted")
	}
	if _, err := instance.GetUserStats(context.Background(), nil); err != nil {
		t.Fatalf("empty request payload rejected: %v", err)
	}
	if _, err := (&supervisor{}).GetUserStats(context.Background(), &emptypb.Empty{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("missing stats adapter error = %v", err)
	}
	instance.stats = runtimeStatsStub{err: errors.New("stats failure")}
	if _, err := instance.GetUserStats(context.Background(), &emptypb.Empty{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("stats adapter error = %v", err)
	}
}
