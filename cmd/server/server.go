package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	grpcmiddleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpczap "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	gcred "github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/server"
	pb "github.com/annetutil/gnetcli/pkg/server/proto"
)

func path(rel string) string {
	_, currentFile, _, _ := runtime.Caller(0)
	basepath := filepath.Dir(currentFile)
	if filepath.IsAbs(rel) {
		return rel
	}

	return filepath.Join(basepath, rel)
}

func parseAuth(basicAuth string) (string, gcred.Secret) {
	basicAuthSplit := strings.SplitN(basicAuth, ":", 2)
	if len(basicAuthSplit) != 2 {
		panic("wrong basicAuth format")
	}
	return basicAuthSplit[0], gcred.Secret(basicAuthSplit[1])
}

func main() {
	tls := flag.Bool("tls", false, "Connection uses TLS if true, else plain TCP")
	certFile := flag.String("cert-file", "", "The TLS cert file")
	keyFile := flag.String("key-file", "", "The TLS key file")
	basicAuth := flag.String("basic-auth", "", "Authenticate client using Basic auth")
	devLogin := flag.String("dev-login", "", "Authenticate password")
	devPassword := flag.String("dev-password", "", "Authorization password")
	devUseAgent := flag.Bool("dev-enable-agent", false, "Enable pubkey auth using ssh-agent")
	port := flag.Int("port", 50051, "The server port")
	disableTcp := flag.Bool("disable-tcp", false, "Disable TCP listener")
	unixSocket := flag.String("unix-socket", "", "Unix socket path")
	debug := flag.Bool("debug", false, "set debug log level")
	flag.Parse()
	logConfig := zap.NewProductionConfig()
	if *debug {
		logConfig = zap.NewDevelopmentConfig()
	}

	logger := zap.Must(logConfig.Build())
	var listeners []net.Listener
	if len(*unixSocket) > 0 {
		logger.Debug("init unix socket", zap.String("path", *unixSocket))
		unixSocketLn, err := newUnixSocket(*unixSocket)
		if err != nil {
			logger.Panic("unix socket error", zap.Error(err))
		}
		listeners = append(listeners, unixSocketLn)
	}
	if !*disableTcp {
		address := fmt.Sprintf("localhost:%d", *port)
		logger.Debug("init tcp socket", zap.String("address", address))
		tcpSocketLn, err := newTcpSocket(address)
		if err != nil {
			logger.Panic("tcp socket error", zap.Error(err))
		}
		listeners = append(listeners, tcpSocketLn)
	}
	if len(listeners) == 0 {
		logger.Panic("specify tcp or unix socket")
	}
	var opts []grpc.ServerOption
	if *tls {
		if *certFile == "" {
			*certFile = path("x509/server_cert.pem")
		}
		if *keyFile == "" {
			*keyFile = path("x509/server_key.pem")
		}
		creds, err := credentials.NewServerTLSFromFile(*certFile, *keyFile)
		if err != nil {
			log.Fatalf("Failed to generate credentials: %v", err)
		}
		opts = []grpc.ServerOption{grpc.Creds(creds)}
	}
	var auth *server.Auth
	envBasicAuth, exists := os.LookupEnv("BASIC_AUTH")
	if len(*basicAuth) > 0 {
		login, secret := parseAuth(*basicAuth)
		logger.Info("auth string assigned with flag")
		auth = server.NewAuth(logger, login, secret)
	} else if exists {
		login, secret := parseAuth(envBasicAuth)
		logger.Info("auth string assigned with env")
		auth = server.NewAuth(logger, login, secret)
	} else {
		logger.Error("server is working in dangerous authentication free mode")
		auth = server.NewAuthInsecure(logger)
	}

	opts = append(opts,
		grpc.UnaryInterceptor(grpcmiddleware.ChainUnaryServer(
			grpczap.UnaryServerInterceptor(logger),
			auth.AuthenticateUnary,
		)),
		grpc.StreamInterceptor(grpcmiddleware.ChainStreamServer(
			grpczap.StreamServerInterceptor(logger),
			auth.AuthenticateStream,
		)),
	)
	grpcServer := grpc.NewServer(opts...)

	serverOpts := []server.Option{server.WithLogger(logger)}
	devCreds := server.BuildEmptyCreds(logger)
	if len(*devLogin) > 0 || len(*devPassword) > 0 || *devUseAgent {
		devCreds = server.BuildCreds(*devLogin, *devPassword, *devUseAgent, logger)
	}
	serverOpts = append(serverOpts, server.WithCredentials(devCreds))

	s := server.New(serverOpts...)
	pb.RegisterGnetcliServer(grpcServer, s)
	reflection.Register(grpcServer)
	ctx := context.Background()
	wg, _ := errgroup.WithContext(ctx)
	for _, listener := range listeners {
		wListener := listener
		wg.Go(func() error {
			return grpcServer.Serve(wListener)
		})
	}
	err := wg.Wait()
	panic(err)
}

func newUnixSocket(path string) (net.Listener, error) {
	if err := syscall.Unlink(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	return l, nil
}

func newTcpSocket(address string) (net.Listener, error) {
	lis, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	return lis, nil
}
