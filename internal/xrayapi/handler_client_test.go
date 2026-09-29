package xrayapi

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"xray-easy/internal/xrayapi/core"
	handlercommand "xray-easy/internal/xrayapi/handler"
	"xray-easy/internal/xrayapi/protocol"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

type handlerTestServer struct {
	handlercommand.UnimplementedHandlerServiceServer
	tags     []*core.InboundHandlerConfig
	users    []*protocol.User
	listErr  error
	usersErr error
	alterErr error
	alters   []*handlercommand.AlterInboundRequest
	queries  []*handlercommand.GetInboundUserRequest
	listCall int
}

func (s *handlerTestServer) ListInbounds(_ context.Context, request *handlercommand.ListInboundsRequest) (*handlercommand.ListInboundsResponse, error) {
	s.listCall++
	if !request.GetIsOnlyTags() {
		return nil, errors.New("expected tag-only inbound request")
	}
	if s.listErr != nil {
		return nil, s.listErr
	}
	return &handlercommand.ListInboundsResponse{Inbounds: s.tags}, nil
}

func (s *handlerTestServer) GetInboundUsers(_ context.Context, request *handlercommand.GetInboundUserRequest) (*handlercommand.GetInboundUserResponse, error) {
	s.queries = append(s.queries, proto.Clone(request).(*handlercommand.GetInboundUserRequest))
	if request.GetTag() == "" {
		return nil, errors.New("inbound tag is required")
	}
	if s.usersErr != nil {
		return nil, s.usersErr
	}
	return &handlercommand.GetInboundUserResponse{Users: s.users}, nil
}

func (s *handlerTestServer) AlterInbound(_ context.Context, request *handlercommand.AlterInboundRequest) (*handlercommand.AlterInboundResponse, error) {
	s.alters = append(s.alters, proto.Clone(request).(*handlercommand.AlterInboundRequest))
	if s.alterErr != nil {
		return nil, s.alterErr
	}
	return &handlercommand.AlterInboundResponse{}, nil
}

func newHandlerTestClient(t *testing.T, implementation handlercommand.HandlerServiceServer) *HandlerClient {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	handlercommand.RegisterHandlerServiceServer(server, implementation)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})
	client := NewHandlerClient("passthrough:///handler-test")
	client.dialOptions = []grpc.DialOption{grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return listener.DialContext(ctx)
	})}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestHandlerClientAddsAndRemovesVLESSUsers(t *testing.T) {
	implementation := &handlerTestServer{tags: []*core.InboundHandlerConfig{{Tag: inboundTag}}}
	client := newHandlerTestClient(t, implementation)
	ctx := context.Background()
	for _, test := range []struct{ email, uuid, flow string }{
		{"phone@example.test", "uuid-123", "xtls-rprx-vision"},
		{"legacy@example.test", "uuid-456", ""},
	} {
		if err := client.AddUser(ctx, test.email, test.uuid, test.flow); err != nil {
			t.Fatal(err)
		}
	}
	if err := client.RemoveUser(ctx, "phone@example.test"); err != nil {
		t.Fatal(err)
	}
	if len(implementation.alters) != 3 {
		t.Fatalf("AlterInbound calls = %d, want 3", len(implementation.alters))
	}
	for index, test := range []struct{ email, uuid, flow, typeName string }{
		{"phone@example.test", "uuid-123", "xtls-rprx-vision", "xray.app.proxyman.command.AddUserOperation"},
		{"legacy@example.test", "uuid-456", "", "xray.app.proxyman.command.AddUserOperation"},
		{"phone@example.test", "", "", "xray.app.proxyman.command.RemoveUserOperation"},
	} {
		request := implementation.alters[index]
		if request.GetTag() != inboundTag || request.GetOperation().GetType() != test.typeName {
			t.Fatalf("operation %d tag/type = %q/%q", index, request.GetTag(), request.GetOperation().GetType())
		}
		if index < 2 {
			var operation handlercommand.AddUserOperation
			if err := proto.Unmarshal(request.GetOperation().GetValue(), &operation); err != nil {
				t.Fatal(err)
			}
			user := operation.GetUser()
			if user == nil || user.GetEmail() != test.email || user.GetAccount().GetType() != "xray.proxy.vless.Account" {
				t.Fatalf("AddUser operation = %+v", user)
			}
			gotUUID, gotFlow := decodeVLESSAccount(t, user.GetAccount().GetValue())
			if gotUUID != test.uuid || gotFlow != test.flow {
				t.Errorf("VLESS account = %q/%q, want %q/%q", gotUUID, gotFlow, test.uuid, test.flow)
			}
		} else {
			var operation handlercommand.RemoveUserOperation
			if err := proto.Unmarshal(request.GetOperation().GetValue(), &operation); err != nil {
				t.Fatal(err)
			}
			if operation.GetEmail() != test.email {
				t.Fatalf("RemoveUser email = %q, want %q", operation.GetEmail(), test.email)
			}
		}
	}
	if implementation.listCall != 3 {
		t.Fatalf("inbound resolution calls = %d, want 3", implementation.listCall)
	}
}

func TestHandlerClientUsesDedicatedHysteriaInboundAndAccountEncoding(t *testing.T) {
	implementation := &handlerTestServer{
		tags:  []*core.InboundHandlerConfig{{Tag: inboundTag}, {Tag: "hysteria2"}},
		users: []*protocol.User{{Email: "phone@example.test"}},
	}
	client := newHandlerTestClient(t, implementation)
	ctx := context.Background()
	if err := client.AddHysteriaUser(ctx, "phone@example.test", "device-secret"); err != nil {
		t.Fatal(err)
	}
	users, err := client.UsersInInbound(ctx, "hysteria2")
	if err != nil || len(users) != 1 || users[0] != "phone@example.test" || len(implementation.queries) != 1 || implementation.queries[0].GetTag() != "hysteria2" {
		t.Fatalf("Hysteria users = %v, queries=%v, err=%v", users, implementation.queries, err)
	}
	if err := client.RemoveHysteriaUser(ctx, "phone@example.test"); err != nil {
		t.Fatal(err)
	}
	if len(implementation.alters) != 2 || implementation.alters[0].GetTag() != "hysteria2" || implementation.alters[1].GetTag() != "hysteria2" {
		t.Fatalf("Hysteria mutations used another inbound: %+v", implementation.alters)
	}
	var added handlercommand.AddUserOperation
	if err := proto.Unmarshal(implementation.alters[0].GetOperation().GetValue(), &added); err != nil {
		t.Fatal(err)
	}
	account := added.GetUser().GetAccount()
	if account.GetType() != "xray.proxy.hysteria.Account" {
		t.Fatalf("Hysteria account type = %q", account.GetType())
	}
	number, wireType, tagLength := protowire.ConsumeTag(account.GetValue())
	auth, _ := protowire.ConsumeString(account.GetValue()[tagLength:])
	if number != 1 || wireType != protowire.BytesType || auth != "device-secret" {
		t.Fatalf("Hysteria account auth field = %d/%v/%q", number, wireType, auth)
	}
	var removed handlercommand.RemoveUserOperation
	if err := proto.Unmarshal(implementation.alters[1].GetOperation().GetValue(), &removed); err != nil || removed.GetEmail() != "phone@example.test" {
		t.Fatalf("Hysteria removal = %v, %v", removed.GetEmail(), err)
	}
}

func decodeVLESSAccount(t *testing.T, value []byte) (string, string) {
	t.Helper()
	var uuid, flow string
	for len(value) > 0 {
		number, wireType, tagLen := protowire.ConsumeTag(value)
		if tagLen < 0 {
			t.Fatalf("invalid VLESS account tag: %v", protowire.ParseError(tagLen))
		}
		value = value[tagLen:]
		if wireType != protowire.BytesType {
			t.Fatalf("unexpected VLESS account wire type %v", wireType)
		}
		field, consumed := protowire.ConsumeString(value)
		if consumed < 0 {
			t.Fatalf("invalid VLESS account field: %v", protowire.ParseError(consumed))
		}
		value = value[consumed:]
		switch number {
		case 1:
			uuid = field
		case 2:
			flow = field
		default:
			t.Fatalf("unexpected VLESS account field %d", number)
		}
	}
	return uuid, flow
}

func TestHandlerClientUsersFiltersEmptyEntriesAndResolvesInboundTag(t *testing.T) {
	for _, test := range []struct {
		name    string
		tags    []*core.InboundHandlerConfig
		wantTag string
		wantErr bool
	}{
		{"exact tag wins", []*core.InboundHandlerConfig{{Tag: "other"}, {Tag: inboundTag}}, inboundTag, false},
		{"single inbound fallback", []*core.InboundHandlerConfig{{Tag: "custom"}}, "custom", false},
		{"no inbound", nil, "", true},
		{"ambiguous inbounds", []*core.InboundHandlerConfig{{Tag: "one"}, {Tag: "two"}}, "", true},
		{"empty tags", []*core.InboundHandlerConfig{nil, {}, {Tag: ""}}, "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			implementation := &handlerTestServer{tags: test.tags, users: []*protocol.User{nil, {}, {Email: ""}, {Email: "phone@example.test"}, {Email: "tablet@example.test"}}}
			client := newHandlerTestClient(t, implementation)
			defer client.Close()
			users, err := client.Users(context.Background())
			if (err != nil) != test.wantErr {
				t.Fatalf("Users() error = %v, wantErr=%v", err, test.wantErr)
			}
			if test.wantErr {
				return
			}
			if len(users) != 2 || users[0] != "phone@example.test" || users[1] != "tablet@example.test" {
				t.Fatalf("Users() = %v", users)
			}
			if implementation.listCall != 1 {
				t.Fatalf("ListInbounds called %d times", implementation.listCall)
			}
			if len(implementation.queries) != 1 || implementation.queries[0].GetTag() != test.wantTag {
				t.Fatalf("GetInboundUsers query = %+v, want tag %q", implementation.queries, test.wantTag)
			}
		})
	}
}

func TestHandlerClientPropagatesRPCFailuresAndResetsConnection(t *testing.T) {
	implementation := &handlerTestServer{tags: []*core.InboundHandlerConfig{{Tag: inboundTag}}, usersErr: status.Error(codes.Unavailable, "temporary")}
	client := newHandlerTestClient(t, implementation)
	if _, err := client.Users(context.Background()); err == nil || !strings.Contains(err.Error(), "get inbound users") {
		t.Fatalf("Users RPC error = %v", err)
	}
	if client.conn != nil || client.client != nil {
		t.Fatal("failed users RPC did not reset connection state")
	}
	implementation.usersErr = nil
	implementation.users = []*protocol.User{{Email: "recovered@example.test"}}
	users, err := client.Users(context.Background())
	if err != nil || len(users) != 1 || users[0] != "recovered@example.test" {
		t.Fatalf("Users after reconnect = %v, %v", users, err)
	}
}

func TestHandlerClientErrorsForEmptyAddressAndDialFailure(t *testing.T) {
	if err := NewHandlerClient("").AddUser(context.Background(), "a@b", "uuid", "flow"); err == nil {
		t.Fatal("empty Xray API address accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	client := NewHandlerClient("handler-test")
	client.dialOptions = []grpc.DialOption{grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return nil, errors.New("dial denied") })}
	if _, err := client.Users(ctx); err == nil || !strings.Contains(err.Error(), "connect to Xray API") {
		t.Fatalf("dial failure = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHandlerClientResetsConnectionOnListAndAlterErrors(t *testing.T) {
	for _, test := range []struct {
		name           string
		implementation *handlerTestServer
		operation      func(*HandlerClient) error
	}{
		{"list error", &handlerTestServer{listErr: status.Error(codes.Unavailable, "list failed")}, func(c *HandlerClient) error { return c.RemoveUser(context.Background(), "phone@example.test") }},
		{"alter error", &handlerTestServer{tags: []*core.InboundHandlerConfig{{Tag: inboundTag}}, alterErr: status.Error(codes.Unavailable, "alter failed")}, func(c *HandlerClient) error { return c.RemoveUser(context.Background(), "phone@example.test") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := newHandlerTestClient(t, test.implementation)
			if err := test.operation(client); err == nil {
				t.Fatal("RPC failure not returned")
			}
			if client.conn != nil || client.client != nil {
				t.Fatal("RPC failure did not reset connection")
			}
		})
	}
}

func TestHandlerClientCloseWithoutConnectionIsSafe(t *testing.T) {
	implementation := &handlerTestServer{tags: []*core.InboundHandlerConfig{{Tag: inboundTag}}}
	client := newHandlerTestClient(t, implementation)
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if client.conn != nil {
		t.Fatal("Close created a connection")
	}
}
