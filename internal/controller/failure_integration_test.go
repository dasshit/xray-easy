package controller

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"xray-easy/internal/interaction"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const failureTestToken = "controller-integration-token"

type failureTestHarness struct {
	client   *Client
	server   *grpc.Server
	listener *bufconn.Listener
	conn     *grpc.ClientConn
}

func newFailureTestHarness(t *testing.T, service *Service) *failureTestHarness {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(grpc.ChainUnaryInterceptor(LoggingInterceptor("controller-integration"), AuthInterceptor(failureTestToken)))
	RegisterRPC(server, service)
	go func() { _ = server.Serve(listener) }()
	conn, err := grpc.NewClient("passthrough:///controller-failure-integration", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		server.Stop()
		_ = listener.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.Stop()
		_ = conn.Close()
		_ = listener.Close()
	})
	return &failureTestHarness{client: NewClientWithConn(conn, failureTestToken), server: server, listener: listener, conn: conn}
}

func TestControllerClientRecoversAfterControllerRestart(t *testing.T) {
	var mu sync.RWMutex
	var active *bufconn.Listener
	newListener := func() *bufconn.Listener {
		listener := bufconn.Listen(1 << 20)
		mu.Lock()
		active = listener
		mu.Unlock()
		return listener
	}
	dialer := func(context.Context, string) (net.Conn, error) {
		mu.RLock()
		listener := active
		mu.RUnlock()
		if listener == nil {
			return nil, errors.New("Controller listener is unavailable")
		}
		return listener.Dial()
	}
	startServer := func(listener *bufconn.Listener) *grpc.Server {
		server := grpc.NewServer(grpc.ChainUnaryInterceptor(LoggingInterceptor("controller-restart-integration"), AuthInterceptor(failureTestToken)))
		RegisterRPC(server, NewService(&fakeRuntime{}))
		go func() { _ = server.Serve(listener) }()
		return server
	}

	firstListener := newListener()
	firstServer := startServer(firstListener)
	conn, err := grpc.NewClient("passthrough:///controller-restart-integration", grpc.WithContextDialer(dialer), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := NewClientWithConn(conn, failureTestToken)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Health(ctx); err != nil {
		t.Fatalf("initial Controller health = %v", err)
	}

	firstServer.Stop()
	_ = firstListener.Close()
	mu.Lock()
	active = nil
	mu.Unlock()
	outage, stopOutage := context.WithTimeout(context.Background(), 150*time.Millisecond)
	err = client.Health(outage)
	stopOutage()
	if status.Code(err) != codes.DeadlineExceeded && status.Code(err) != codes.Unavailable {
		t.Fatalf("request while Controller is stopped = %v, want deadline/unavailable", err)
	}

	secondListener := newListener()
	secondServer := startServer(secondListener)
	defer secondServer.Stop()
	defer secondListener.Close()
	recovery, stopRecovery := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopRecovery()
	for {
		err := client.Health(recovery)
		if err == nil {
			break
		}
		if status.Code(err) != codes.Unavailable {
			t.Fatalf("same backend client did not recover after Controller restart: %v", err)
		}
		select {
		case <-recovery.Done():
			t.Fatalf("same backend client did not reconnect before deadline: %v", recovery.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func TestControllerSurfacesAdapterOutagesAndPropagatesDeadlines(t *testing.T) {
	t.Run("Xray unavailable", func(t *testing.T) {
		harness := newFailureTestHarness(t, NewService(&fakeRuntime{err: status.Error(codes.Unavailable, "Xray stopped")}))
		if err := harness.client.Health(context.Background()); status.Code(err) != codes.Unavailable {
			t.Fatalf("Xray outage returned %v", err)
		}
	})
	t.Run("optional AWG disabled", func(t *testing.T) {
		harness := newFailureTestHarness(t, NewService(&fakeRuntime{}))
		if err := harness.client.Health(context.Background()); err != nil {
			t.Fatalf("Xray health failed because optional AWG is absent: %v", err)
		}
		if _, err := harness.client.AWG().Status(context.Background()); status.Code(err) != codes.Unavailable {
			t.Fatalf("disabled AWG status returned %v", err)
		}
	})
	t.Run("AWG adapter unavailable", func(t *testing.T) {
		awg := &fakeAWGRuntime{err: status.Error(codes.Unavailable, "AWG service stopped")}
		harness := newFailureTestHarness(t, NewServiceWithAdapters(&fakeRuntime{}, nil, nil, awg))
		if err := harness.client.Health(context.Background()); err != nil {
			t.Fatalf("Xray health failed because AWG is unavailable: %v", err)
		}
		if _, err := harness.client.AWG().Status(context.Background()); status.Code(err) != codes.Unavailable {
			t.Fatalf("AWG outage returned %v", err)
		}
	})
	t.Run("request deadline cancels adapter call", func(t *testing.T) {
		handler := &deadlineXrayHandler{started: make(chan struct{}), cancelled: make(chan struct{})}
		harness := newFailureTestHarness(t, NewServiceWithAdapters(&fakeRuntime{}, handler, nil, nil))
		ctx, cancel := context.WithTimeout(interaction.WithOperationID(context.Background(), "abcdef0123456789abcdef0123456789"), 60*time.Millisecond)
		defer cancel()
		result := make(chan error, 1)
		go func() { result <- harness.client.AddUser(ctx, "device@xray-easy", "stable-id", "vision") }()
		select {
		case <-handler.started:
		case <-time.After(2 * time.Second):
			t.Fatal("Controller did not invoke Xray adapter")
		}
		select {
		case err := <-result:
			if status.Code(err) != codes.DeadlineExceeded {
				t.Fatalf("deadline-limited AddUser returned %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("deadline-limited RPC did not return")
		}
		select {
		case <-handler.cancelled:
		case <-time.After(2 * time.Second):
			t.Fatal("Controller did not propagate cancellation to Xray adapter")
		}
	})
}

type deadlineXrayHandler struct {
	fakeXrayHandler
	started   chan struct{}
	cancelled chan struct{}
}

func (h *deadlineXrayHandler) AddUser(ctx context.Context, _, _, _ string) error {
	close(h.started)
	<-ctx.Done()
	close(h.cancelled)
	return ctx.Err()
}

func (*deadlineXrayHandler) Users(context.Context) ([]string, error) { return nil, nil }

type responseLossInvoker struct {
	rpcInvoker
	mu       sync.Mutex
	method   string
	lostOnce bool
}

func (i *responseLossInvoker) Invoke(ctx context.Context, method string, request, response any, options ...grpc.CallOption) error {
	err := i.rpcInvoker.Invoke(ctx, method, request, response, options...)
	if err != nil || method != i.method {
		return err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.lostOnce {
		return nil
	}
	i.lostOnce = true
	return status.Error(codes.Unavailable, "simulated response loss after runtime commit")
}

func TestXrayMutationReplayAfterControllerResponseLoss(t *testing.T) {
	handler := &fakeXrayHandler{}
	harness := newFailureTestHarness(t, NewServiceWithAdapters(&fakeRuntime{}, handler, nil, nil))
	harness.client.connection = &responseLossInvoker{rpcInvoker: harness.conn, method: "/" + RPCServiceName + "/AddDeviceUser"}
	requestID := "0123456789abcdef0123456789abcdef"
	operationID := "abcdef0123456789abcdef0123456789"
	base := interaction.WithStateRevision(interaction.WithOperationID(interaction.WithRequestID(context.Background(), requestID), operationID), 4)
	if err := harness.client.AddUser(base, "device@xray-easy", "stable-id", "vision"); status.Code(err) != codes.Unavailable {
		t.Fatalf("first add with simulated lost response = %v", err)
	}
	retry := interaction.WithAttempt(base, 2)
	if err := harness.client.AddUser(retry, "device@xray-easy", "stable-id", "vision"); err != nil {
		t.Fatalf("replay after response loss = %v", err)
	}
	if handler.adds != 1 || len(handler.users) != 1 {
		t.Fatalf("lost-response replay duplicated Xray user: add calls=%d users=%v", handler.adds, handler.users)
	}
	if len(handler.traces) != 3 {
		t.Fatalf("expected list/add/replay traces, got %+v", handler.traces)
	}
	for index, trace := range handler.traces {
		wantAttempt := 1
		if index == 2 {
			wantAttempt = 2
		}
		if trace.OperationID != operationID || trace.Attempt != wantAttempt || trace.StateRevision != 4 {
			t.Errorf("adapter trace[%d] = %+v", index, trace)
		}
	}
	if len(handler.users) != 1 || handler.users[0] != "device@xray-easy" {
		t.Fatalf("adapter did not observe stable operation/revision across replay: %+v", handler.traces)
	}
}

var _ XrayHandlerRuntime = (*deadlineXrayHandler)(nil)
