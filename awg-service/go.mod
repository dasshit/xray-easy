module xray-easy/awg-service

go 1.25.0

require (
	xray-easy/awg-contract v0.0.0
	github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260828
	golang.org/x/crypto v0.42.0
	google.golang.org/grpc v1.76.0
	google.golang.org/protobuf v1.36.6
)

replace xray-easy/awg-contract => ../awg-contract

require (
	golang.org/x/net v0.44.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
	golang.org/x/text v0.29.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250804133106-a7a43d27e69b // indirect
)
