// Package controller contains the private gRPC Controller boundary and its
// adapters to protocol runtime services.
package controller

import (
	"google.golang.org/grpc"
	controllerv1 "xray-easy/internal/controller/api/v1"
)

const RPCServiceName = "xrayeasy.controller.v1.Controller"

// RPCServer is the generated transport-level Controller API.
type RPCServer = controllerv1.ControllerServer

// RegisterRPC registers the generated typed Controller gRPC service.
func RegisterRPC(registrar grpc.ServiceRegistrar, api RPCServer) {
	controllerv1.RegisterControllerServer(registrar, api)
}
