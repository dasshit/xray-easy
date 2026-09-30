package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
)

func (s *supervisor) Health(_ context.Context, _ *emptypb.Empty) (*structpb.Struct, error) {
	s.mu.Lock()
	state := s.state
	s.mu.Unlock()
	if state != "running" && state != "no-config" {
		return nil, status.Errorf(codes.Unavailable, "supervisor is not ready: %s", state)
	}
	return rpcResponse(map[string]any{"ok": true, "state": state, "protocol": protocolVersion})
}

func (s *supervisor) GetStatus(_ context.Context, _ *emptypb.Empty) (*structpb.Struct, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pid := 0
	if s.child != nil && s.child.Process != nil {
		pid = s.child.Process.Pid
	}
	return rpcResponse(map[string]any{
		"protocol":      protocolVersion,
		"xray_version":  s.xrayVersion,
		"state":         s.state,
		"pid":           pid,
		"config_path":   s.configPath,
		"last_error":    redact(s.lastError),
		"last_exit":     redact(s.lastExit),
		"restart_count": s.restartCount,
		"started_at":    s.startedAt.Format(time.RFC3339Nano),
	})
}

func (s *supervisor) GetLogs(_ context.Context, _ *emptypb.Empty) (*structpb.Struct, error) {
	lines := s.log.all()
	values := make([]any, len(lines))
	for index, line := range lines {
		values[index] = line
	}
	return rpcResponse(map[string]any{"protocol": protocolVersion, "lines": values})
}

func (s *supervisor) ValidateConfig(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	if err := rpcFields(request, "path", "operation_id"); err != nil {
		return nil, err
	}
	path, err := rpcString(request, "path", true)
	if err != nil {
		return nil, err
	}
	operationID, err := rpcString(request, "operation_id", false)
	if err != nil {
		return nil, err
	}
	if err := s.validateContext(ctx, path); err != nil {
		return nil, rpcOperationError(codes.FailedPrecondition, err)
	}
	return rpcResponse(map[string]any{"ok": true, "operation_id": operationID, "protocol": protocolVersion})
}

func (s *supervisor) ApplyConfig(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	if err := rpcFields(request, "path", "operation_id"); err != nil {
		return nil, err
	}
	path, err := rpcString(request, "path", true)
	if err != nil {
		return nil, err
	}
	operationID, err := rpcString(request, "operation_id", true)
	if err != nil {
		return nil, err
	}
	if err := s.applyContext(ctx, path); err != nil {
		return nil, rpcOperationError(codes.FailedPrecondition, err)
	}
	return rpcResponse(map[string]any{"ok": true, "operation_id": operationID, "protocol": protocolVersion})
}

func (s *supervisor) ReplaceInbound(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	if err := rpcFields(request, "candidate_path", "previous_path", "tag", "operation_id"); err != nil {
		return nil, err
	}
	candidatePath, err := rpcString(request, "candidate_path", true)
	if err != nil {
		return nil, err
	}
	previousPath, err := rpcString(request, "previous_path", true)
	if err != nil {
		return nil, err
	}
	tag, err := rpcString(request, "tag", true)
	if err != nil {
		return nil, err
	}
	operationID, err := rpcString(request, "operation_id", true)
	if err != nil {
		return nil, err
	}
	input := replaceInboundRequest{CandidatePath: candidatePath, PreviousPath: previousPath, Tag: tag, OperationID: operationID}
	if err := s.replaceInboundContext(ctx, input); err != nil {
		return nil, rpcOperationError(codes.FailedPrecondition, err)
	}
	return rpcResponse(map[string]any{"ok": true, "operation_id": operationID, "protocol": protocolVersion})
}

func (s *supervisor) ProbeTarget(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	if err := rpcFields(request, "target", "sni"); err != nil {
		return nil, err
	}
	target, err := rpcString(request, "target", true)
	if err != nil {
		return nil, err
	}
	sni, err := rpcString(request, "sni", false)
	if err != nil {
		return nil, err
	}
	probe := s.cfg.probeTargetFn
	if probe == nil {
		probe = probeTargetContext
	}
	if err := probe(ctx, target, sni); err != nil {
		code := codes.Unavailable
		if errors.Is(err, errInvalidProbeTarget) {
			code = codes.InvalidArgument
		}
		return nil, rpcOperationError(code, err)
	}
	return rpcResponse(map[string]any{"ok": true, "target": target, "protocol": protocolVersion})
}

func (s *supervisor) ProbeIPv6(ctx context.Context, _ *emptypb.Empty) (*structpb.Struct, error) {
	probeContext, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	probe := s.ipv6ProbeFn
	if probe == nil {
		probe = probeIPv6
	}
	if err := probe(probeContext); err != nil {
		return nil, rpcOperationError(codes.Unavailable, errors.New("outbound IPv6 TCP probe failed"))
	}
	return rpcResponse(map[string]any{"ok": true, "protocol": protocolVersion})
}

func rpcResponse(fields map[string]any) (*structpb.Struct, error) {
	response, err := structpb.NewStruct(fields)
	if err != nil {
		return nil, fmt.Errorf("encode supervisor response: %w", err)
	}
	return response, nil
}

func rpcString(request *structpb.Struct, field string, required bool) (string, error) {
	if request == nil {
		if required {
			return "", status.Errorf(codes.InvalidArgument, "%s is required", field)
		}
		return "", nil
	}
	value := request.GetFields()[field]
	if value == nil {
		if required {
			return "", status.Errorf(codes.InvalidArgument, "%s is required", field)
		}
		return "", nil
	}
	if _, ok := value.GetKind().(*structpb.Value_StringValue); !ok {
		return "", status.Errorf(codes.InvalidArgument, "%s must be a string", field)
	}
	result := value.GetStringValue()
	if required && result == "" {
		return "", status.Errorf(codes.InvalidArgument, "%s is required", field)
	}
	return result, nil
}

func rpcFields(request *structpb.Struct, allowed ...string) error {
	if request == nil {
		return nil
	}
	allowlist := make(map[string]struct{}, len(allowed))
	for _, field := range allowed {
		allowlist[field] = struct{}{}
	}
	for field := range request.GetFields() {
		if _, ok := allowlist[field]; !ok {
			return status.Errorf(codes.InvalidArgument, "unexpected request field %q", field)
		}
	}
	return nil
}

func rpcOperationError(code codes.Code, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return status.Error(codes.Canceled, "supervisor operation canceled")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return status.Error(codes.DeadlineExceeded, "supervisor operation timed out")
	}
	return status.Error(code, redact(err.Error()))
}
