package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"xray-easy/internal/xrayapi"
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

func (s runtimeStatsStub) Poll(context.Context) ([]xrayapi.UserStats, error) {
	return s.users, s.err
}

func rpcRequest(t *testing.T, fields map[string]any) *structpb.Struct {
	t.Helper()
	value, err := structpb.NewStruct(fields)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestAlterUserRoutesSupportedProtocolsAndRejectsInvalidRequests(t *testing.T) {
	handler := &runtimeHandlerStub{}
	instance := &supervisor{handler: handler}
	for _, test := range []struct {
		name, protocol, action, wantCall string
		fields                           map[string]any
	}{
		{"add vless", "vless", "add", "add-vless", map[string]any{"action": "add", "protocol": "vless", "email": "v@example.test", "id": "uuid", "flow": "xtls-rprx-vision"}},
		{"add vmess", "vmess", "add", "add-vmess", map[string]any{"action": "add", "protocol": "vmess", "email": "m@example.test", "id": "uuid"}},
		{"add hysteria", "hysteria2", "add", "add-hysteria2", map[string]any{"action": "add", "protocol": "hysteria2", "email": "h@example.test", "id": "password"}},
		{"remove vless", "vless", "remove", "remove-vless", map[string]any{"action": "remove", "protocol": "vless", "email": "v@example.test"}},
		{"remove vmess", "vmess", "remove", "remove-vmess", map[string]any{"action": "remove", "protocol": "vmess", "email": "m@example.test"}},
		{"remove hysteria", "hysteria2", "remove", "remove-hysteria2", map[string]any{"action": "remove", "protocol": "hysteria2", "email": "h@example.test"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			response, err := instance.AlterUser(context.Background(), rpcRequest(t, test.fields))
			if err != nil || response.GetFields()["ok"].GetBoolValue() != true {
				t.Fatalf("AlterUser() = %v, %v", response, err)
			}
			if handler.calls[len(handler.calls)-1] != test.wantCall {
				t.Fatalf("handler call = %q, want %q", handler.calls[len(handler.calls)-1], test.wantCall)
			}
		})
	}
	for _, fields := range []map[string]any{
		{"action": "unknown", "protocol": "vless", "email": "v@example.test"},
		{"action": "add", "protocol": "unsupported", "email": "v@example.test", "id": "uuid"},
		{"action": "add", "protocol": "vless", "email": "v@example.test"},
		{"action": "remove", "protocol": "vless", "email": "v@example.test", "id": "secret"},
		{"action": "remove", "protocol": "vless", "email": "v@example.test", "flow": "vision"},
		{"action": "add", "protocol": "vless", "email": "v@example.test", "id": 4},
		{"action": "add", "protocol": "vless", "email": "v@example.test", "id": "uuid", "flow": 4},
		{"action": "add", "protocol": "vless", "email": "v@example.test", "id": "uuid", "extra": true},
		{"action": "remove", "protocol": "unsupported", "email": "v@example.test"},
	} {
		if _, err := instance.AlterUser(context.Background(), rpcRequest(t, fields)); status.Code(err) != codes.InvalidArgument {
			t.Errorf("AlterUser(%v) error = %v, want InvalidArgument", fields, err)
		}
	}
	if _, err := (&supervisor{}).AlterUser(context.Background(), rpcRequest(t, map[string]any{"action": "add", "protocol": "vless", "email": "v@example.test", "id": "uuid"})); status.Code(err) != codes.Unavailable {
		t.Fatalf("missing Handler adapter error = %v", err)
	}
	handler.err = errors.New("runtime failure")
	if _, err := instance.AlterUser(context.Background(), rpcRequest(t, map[string]any{"action": "add", "protocol": "vless", "email": "v@example.test", "id": "uuid"})); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("Handler failure error = %v", err)
	}
	if _, err := instance.AlterUser(context.Background(), rpcRequest(t, map[string]any{"action": "remove", "protocol": "vless", "email": "v@example.test"})); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("Handler remove failure error = %v", err)
	}
}

func TestListUsersRoutesAndHandlesUnavailableRuntime(t *testing.T) {
	handler := &runtimeHandlerStub{users: []string{"one@example.test"}}
	instance := &supervisor{handler: handler}
	for protocol, wantCall := range map[string]string{"vless": "list-vless", "vmess": "list-vmess-tls", "hysteria2": "list-hysteria2"} {
		response, err := instance.ListUsers(context.Background(), rpcRequest(t, map[string]any{"protocol": protocol}))
		if err != nil || response.GetFields()["users"].GetListValue().GetValues()[0].GetStringValue() != "one@example.test" {
			t.Fatalf("ListUsers(%s) = %v, %v", protocol, response, err)
		}
		if handler.calls[len(handler.calls)-1] != wantCall {
			t.Fatalf("call = %q, want %q", handler.calls[len(handler.calls)-1], wantCall)
		}
	}
	for _, fields := range []map[string]any{{}, {"protocol": "unsupported"}, {"protocol": 1}, {"protocol": "vless", "unknown": true}} {
		if _, err := instance.ListUsers(context.Background(), rpcRequest(t, fields)); status.Code(err) != codes.InvalidArgument {
			t.Errorf("ListUsers(%v) error = %v", fields, err)
		}
	}
	if _, err := (&supervisor{}).ListUsers(context.Background(), rpcRequest(t, map[string]any{"protocol": "vless"})); status.Code(err) != codes.Unavailable {
		t.Fatalf("missing Handler error = %v", err)
	}
	handler.err = errors.New("upstream unavailable")
	if _, err := instance.ListUsers(context.Background(), rpcRequest(t, map[string]any{"protocol": "vless"})); status.Code(err) != codes.Unavailable {
		t.Fatalf("Handler error = %v", err)
	}
}

func TestGetUserStatsSerializesCountersAndHidesAdapterErrors(t *testing.T) {
	lastSeen := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	instance := &supervisor{stats: runtimeStatsStub{users: []xrayapi.UserStats{{
		Email: "device@example.test", UploadBytes: 123, DownloadBytes: 456, LastSeen: lastSeen,
		SourceIPs: []xrayapi.IPObservation{{Address: "203.0.113.2", LastSeen: lastSeen}},
	}}}}
	response, err := instance.GetUserStats(context.Background(), &structpb.Struct{})
	if err != nil {
		t.Fatal(err)
	}
	user := response.GetFields()["users"].GetListValue().GetValues()[0].GetStructValue().GetFields()
	if user["upload_bytes"].GetStringValue() != "123" || user["download_bytes"].GetStringValue() != "456" || user["last_seen"].GetStringValue() != lastSeen.Format(time.RFC3339Nano) {
		t.Fatalf("stats response = %v", user)
	}
	ip := user["source_ips"].GetListValue().GetValues()[0].GetStructValue().GetFields()
	if ip["address"].GetStringValue() != "203.0.113.2" || ip["last_seen"].GetStringValue() == "" {
		t.Fatalf("source IP response = %v", ip)
	}
	if runtimeTime(time.Time{}) != "" {
		t.Fatal("zero timestamps should be encoded as empty strings")
	}
	if _, err := instance.GetUserStats(context.Background(), rpcRequest(t, map[string]any{"extra": true})); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("unexpected field error = %v", err)
	}
	if _, err := (&supervisor{}).GetUserStats(context.Background(), &structpb.Struct{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("missing stats adapter error = %v", err)
	}
	instance.stats = runtimeStatsStub{err: errors.New("stats failure")}
	if _, err := instance.GetUserStats(context.Background(), &structpb.Struct{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("stats adapter error = %v", err)
	}
}
