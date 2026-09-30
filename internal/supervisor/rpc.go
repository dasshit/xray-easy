package supervisor

import (
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	supervisorv1 "xray-easy/internal/supervisor/api/v1"
)

const RPCServiceName = "xrayeasy.supervisor.v1.Supervisor"

// RegisterRPC registers the generated typed Supervisor gRPC service.
func RegisterRPC(registrar grpc.ServiceRegistrar, api supervisorv1.SupervisorServer) {
	supervisorv1.RegisterSupervisorServer(registrar, api)
}

// DeterministicBytes serializes a protobuf message with stable field ordering
// for the Supervisor request HMAC.
func DeterministicBytes(message proto.Message) ([]byte, error) {
	return (proto.MarshalOptions{Deterministic: true}).Marshal(message)
}
