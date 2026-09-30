package xrayruntimev1

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestConfigurationRequestRoundTripsOpaqueSnapshot(t *testing.T) {
	configuration := []byte(`{"privateKey":"must-not-be-logged","inbounds":[{"tag":"vless-reality"}]}`)
	want := &ConfigurationRequest{
		ConfigurationJson: configuration,
		OperationId:       "operation-123",
		Revision:          42,
	}

	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(want)
	if err != nil {
		t.Fatalf("marshal runtime configuration request: %v", err)
	}
	got := new(ConfigurationRequest)
	if err := proto.Unmarshal(encoded, got); err != nil {
		t.Fatalf("unmarshal runtime configuration request: %v", err)
	}
	if !bytes.Equal(got.GetConfigurationJson(), configuration) || got.GetOperationId() != want.GetOperationId() || got.GetRevision() != want.GetRevision() {
		t.Fatalf("configuration request round trip = %+v, want %+v", got, want)
	}
}

func TestRuntimeContractIsVersionedAndUsesProtocolEnums(t *testing.T) {
	service := File_runtime_proto.Services().ByName("Runtime")
	if service == nil || string(service.FullName()) != "xrayeasy.xray.v1.Runtime" {
		t.Fatalf("Runtime service descriptor = %v", service)
	}

	for _, method := range []string{"ValidateConfiguration", "ApplyConfiguration", "ReplaceInbound", "AddUser", "RemoveUser", "GetTelemetry"} {
		if service.Methods().ByName(protoreflect.Name(method)) == nil {
			t.Errorf("Runtime service has no %s method", method)
		}
	}

	for _, value := range []Protocol{Protocol_PROTOCOL_VLESS, Protocol_PROTOCOL_VMESS, Protocol_PROTOCOL_HYSTERIA2} {
		if value == Protocol_PROTOCOL_UNSPECIFIED {
			t.Fatalf("protocol %v resolves to unspecified", value)
		}
		if Protocol_name[int32(value)] == "" {
			t.Errorf("protocol enum %d is not named", value)
		}
	}

	configurationRequest := File_runtime_proto.Messages().ByName("ConfigurationRequest")
	if configurationRequest.Fields().ByName("path") != nil {
		t.Fatal("ConfigurationRequest must carry a snapshot instead of a container filesystem path")
	}
	if configurationRequest.Fields().ByName("configuration_json") == nil || configurationRequest.Fields().ByName("operation_id") == nil || configurationRequest.Fields().ByName("revision") == nil {
		t.Fatal("ConfigurationRequest is missing its snapshot or operation fence")
	}
}
