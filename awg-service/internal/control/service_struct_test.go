package control

import (
	"context"
	"encoding/json"

	awgapi "xray-easy/awg-contract/api/v1"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
)

// structService adapts the old direct unit-test helpers to the new typed
// service implementation. It is test-only: the production gRPC service has
// no google.protobuf.Struct methods or wire compatibility path.
type structService struct{ *Service }

func newStructService(manager *Manager, options Options) *structService {
	return &structService{Service: NewService(manager, options)}
}

func decodeTestRequest(input *structpb.Struct, output proto.Message) error {
	if input == nil {
		return nil
	}
	data, err := protojson.Marshal(input)
	if err != nil {
		return err
	}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(data, output); err != nil {
		return status.Error(codes.InvalidArgument, "malformed test request")
	}
	return nil
}

func encodeTestResponse(input proto.Message) (*structpb.Struct, error) {
	data, err := protojson.Marshal(input)
	if err != nil {
		return nil, err
	}
	fields := map[string]any{}
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	return structpb.NewStruct(fields)
}

func (s *structService) GetStatus(ctx context.Context, _ *structpb.Struct) (*structpb.Struct, error) {
	response, err := s.Service.GetStatus(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, err
	}
	return encodeTestResponse(response)
}
func (s *structService) ListPeers(ctx context.Context, _ *structpb.Struct) (*structpb.Struct, error) {
	response, err := s.Service.ListPeers(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, err
	}
	return encodeTestResponse(response)
}
func (s *structService) GetPeerStats(ctx context.Context, _ *structpb.Struct) (*structpb.Struct, error) {
	response, err := s.Service.GetPeerStats(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, err
	}
	return encodeTestResponse(response)
}
func (s *structService) CreatePeer(ctx context.Context, input *structpb.Struct) (*structpb.Struct, error) {
	request := new(awgapi.CreatePeerRequest)
	if err := decodeTestRequest(input, request); err != nil {
		return nil, err
	}
	response, err := s.Service.CreatePeer(ctx, request)
	if err != nil {
		return nil, err
	}
	return encodeTestResponse(response)
}
func (s *structService) AddPeer(ctx context.Context, input *structpb.Struct) (*structpb.Struct, error) {
	request := new(awgapi.AddPeerRequest)
	if err := decodeTestRequest(input, request); err != nil {
		return nil, err
	}
	response, err := s.Service.AddPeer(ctx, request)
	if err != nil {
		return nil, err
	}
	return encodeTestResponse(response)
}
func (s *structService) RemovePeer(ctx context.Context, input *structpb.Struct) (*structpb.Struct, error) {
	request := new(awgapi.RemovePeerRequest)
	if err := decodeTestRequest(input, request); err != nil {
		return nil, err
	}
	response, err := s.Service.RemovePeer(ctx, request)
	if err != nil {
		return nil, err
	}
	return encodeTestResponse(response)
}
func (s *structService) GetClientConfig(ctx context.Context, input *structpb.Struct) (*structpb.Struct, error) {
	request := new(awgapi.GetClientConfigRequest)
	if err := decodeTestRequest(input, request); err != nil {
		return nil, err
	}
	response, err := s.Service.GetClientConfig(ctx, request)
	if err != nil {
		return nil, err
	}
	return encodeTestResponse(response)
}
func (s *structService) ExportBackup(ctx context.Context, _ *structpb.Struct) (*structpb.Struct, error) {
	response, err := s.Service.ExportBackup(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, err
	}
	return encodeTestResponse(response)
}
func (s *structService) RestoreBackup(ctx context.Context, input *structpb.Struct) (*structpb.Struct, error) {
	request := new(awgapi.RestoreBackupRequest)
	if err := decodeTestRequest(input, request); err != nil {
		return nil, err
	}
	response, err := s.Service.RestoreBackup(ctx, request)
	if err != nil {
		return nil, err
	}
	return encodeTestResponse(response)
}
func (s *structService) RenderClientConfig(ctx context.Context, input *structpb.Struct) (*structpb.Struct, error) {
	request := new(awgapi.RenderClientConfigRequest)
	if err := decodeTestRequest(input, request); err != nil {
		return nil, err
	}
	response, err := s.Service.RenderClientConfig(ctx, request)
	if err != nil {
		return nil, err
	}
	return encodeTestResponse(response)
}
