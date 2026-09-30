package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"

	supervisorapi "xray-easy/internal/supervisor"
)

func newSupervisorGRPCServer(instance *supervisor) *grpc.Server {
	server := grpc.NewServer(
		grpc.MaxRecvMsgSize(24<<20),
		grpc.MaxSendMsgSize(24<<20),
		grpc.UnaryInterceptor(instance.unaryAuthInterceptor),
	)
	supervisorapi.RegisterRPC(server, instance)
	return server
}

func runSupervisor(cfg *config, signals <-chan os.Signal) error {
	instance := newSupervisor(cfg)
	defer instance.closeRuntimeClients()
	if instance.revisions.err != nil {
		return fmt.Errorf("load Xray revision fence: %w", instance.revisions.err)
	}
	if err := instance.startInitial(); err != nil {
		return err
	}
	listen := cfg.listenFunc
	if listen == nil {
		listen = net.Listen
	}
	listener, err := listen("tcp", cfg.listen)
	if err != nil {
		instance.stopChild()
		return fmt.Errorf("listen for supervisor gRPC: %w", err)
	}
	grpcServer := newSupervisorGRPCServer(instance)
	serveErr := make(chan error, 1)
	go func() { serveErr <- grpcServer.Serve(listener) }()
	instance.logf("supervisor gRPC API listening on %s", cfg.listen)
	select {
	case <-signals:
		stopped := make(chan struct{})
		go func() {
			grpcServer.GracefulStop()
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-time.After(cfg.grace):
			grpcServer.Stop()
		}
	case err := <-serveErr:
		if !errors.Is(err, grpc.ErrServerStopped) {
			grpcServer.Stop()
			instance.stopChild()
			return fmt.Errorf("supervisor gRPC server stopped: %w", err)
		}
	}
	instance.stopChild()
	return nil
}
