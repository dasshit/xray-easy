package main

import (
	"context"
	"errors"
	"time"

	supervisorv1 "xray-easy/internal/supervisor/api/v1"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *supervisor) Health(context.Context, *emptypb.Empty) (*supervisorv1.HealthResponse, error) {
	s.mu.Lock()
	state := s.state
	s.mu.Unlock()
	if state != "running" && state != "no-config" {
		return nil, status.Errorf(codes.Unavailable, "supervisor is not ready: %s", state)
	}
	return &supervisorv1.HealthResponse{Ok: true, State: state, Protocol: protocolVersion}, nil
}

func (s *supervisor) GetStatus(context.Context, *emptypb.Empty) (*supervisorv1.SupervisorStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pid := int32(0)
	if s.child != nil && s.child.Process != nil {
		pid = int32(s.child.Process.Pid)
	}
	response := &supervisorv1.SupervisorStatus{
		Protocol: protocolVersion, XrayVersion: s.xrayVersion, State: s.state, Pid: pid,
		ConfigPath: s.configPath, LastError: redact(s.lastError), LastExit: redact(s.lastExit),
		RestartCount: int32(s.restartCount),
	}
	if !s.startedAt.IsZero() {
		response.StartedAt = timestamppb.New(s.startedAt.UTC())
	}
	return response, nil
}

func (s *supervisor) GetLogs(context.Context, *emptypb.Empty) (*supervisorv1.LogsResponse, error) {
	return &supervisorv1.LogsResponse{Protocol: protocolVersion, Lines: s.log.all()}, nil
}

func (s *supervisor) ValidateConfig(ctx context.Context, request *supervisorv1.ValidateConfigRequest) (*supervisorv1.OperationResponse, error) {
	if request == nil || request.Path == "" {
		return nil, status.Error(codes.InvalidArgument, "path is required")
	}
	if err := s.validateContext(ctx, request.Path); err != nil {
		return nil, rpcOperationError(codes.FailedPrecondition, err)
	}
	return &supervisorv1.OperationResponse{Ok: true, OperationId: request.OperationId, Protocol: protocolVersion}, nil
}

func (s *supervisor) ApplyConfig(ctx context.Context, request *supervisorv1.ApplyConfigRequest) (*supervisorv1.OperationResponse, error) {
	if request == nil || request.Path == "" || request.OperationId == "" {
		return nil, status.Error(codes.InvalidArgument, "path and operation_id are required")
	}
	if err := rpcRevision(request.StateRevision); err != nil {
		return nil, err
	}
	if err := s.applyRevisionContext(ctx, request.Path, request.OperationId, request.StateRevision); err != nil {
		return nil, rpcOperationError(codes.FailedPrecondition, err)
	}
	return &supervisorv1.OperationResponse{Ok: true, OperationId: request.OperationId, Protocol: protocolVersion}, nil
}

func (s *supervisor) ReplaceInbound(ctx context.Context, request *supervisorv1.ReplaceInboundRequest) (*supervisorv1.OperationResponse, error) {
	if request == nil || request.CandidatePath == "" || request.PreviousPath == "" || request.Tag == "" || request.OperationId == "" {
		return nil, status.Error(codes.InvalidArgument, "candidate_path, previous_path, tag, and operation_id are required")
	}
	if err := rpcRevision(request.StateRevision); err != nil {
		return nil, err
	}
	input := replaceInboundRequest{CandidatePath: request.CandidatePath, PreviousPath: request.PreviousPath, Tag: request.Tag, OperationID: request.OperationId}
	if err := s.replaceInboundRevisionContext(ctx, input, request.StateRevision); err != nil {
		return nil, rpcOperationError(codes.FailedPrecondition, err)
	}
	return &supervisorv1.OperationResponse{Ok: true, OperationId: request.OperationId, Protocol: protocolVersion}, nil
}

func rpcRevision(revision int64) error {
	if revision < 1 {
		return status.Error(codes.InvalidArgument, "state_revision must be a positive integer")
	}
	return nil
}

func (s *supervisor) ProbeTarget(ctx context.Context, request *supervisorv1.ProbeTargetRequest) (*supervisorv1.ProbeTargetResponse, error) {
	if request == nil || request.Target == "" {
		return nil, status.Error(codes.InvalidArgument, "target is required")
	}
	probe := s.cfg.probeTargetFn
	if probe == nil {
		probe = probeTargetContext
	}
	if err := probe(ctx, request.Target, request.Sni); err != nil {
		code := codes.Unavailable
		if errors.Is(err, errInvalidProbeTarget) {
			code = codes.InvalidArgument
		}
		return nil, rpcOperationError(code, err)
	}
	return &supervisorv1.ProbeTargetResponse{Ok: true, Target: request.Target, Protocol: protocolVersion}, nil
}

func (s *supervisor) ProbeIPv6(ctx context.Context, _ *emptypb.Empty) (*supervisorv1.ProbeIPv6Response, error) {
	probeContext, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	probe := s.ipv6ProbeFn
	if probe == nil {
		probe = probeIPv6
	}
	if err := probe(probeContext); err != nil {
		return nil, rpcOperationError(codes.Unavailable, errors.New("outbound IPv6 TCP probe failed"))
	}
	return &supervisorv1.ProbeIPv6Response{Ok: true, Protocol: protocolVersion}, nil
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
