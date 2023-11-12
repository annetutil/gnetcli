package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strings"

	grpcmiddleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpczap "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/examples/data"
	"google.golang.org/grpc/reflection"

	gcred "github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/server"
	pb "github.com/annetutil/gnetcli/pkg/server/proto"
)

func main() {
	tls := flag.Bool("tls", false, "Connection uses TLS if true, else plain TCP")
	certFile := flag.String("cert-file", "", "The TLS cert file")
	keyFile := flag.String("key-file", "", "The TLS key file")
	basicAuth := flag.String("basic-auth", "", "Authenticate client using Basic auth")
	devLogin := flag.String("dev-login", "", "Authenticate password")
	devPassword := flag.String("dev-password", "", "Authorization password")
	devUseAgent := flag.Bool("dev-enable-agent", false, "Enable pubkey auth using ssh-agent")
	port := flag.Int("port", 50051, "The server port")
	debug := flag.Bool("debug", false, "set debug log level")
	flag.Parse()
	logConfig := zap.NewProductionConfig()
	if *debug {
		logConfig = zap.NewDevelopmentConfig()
	}

	logger := zap.Must(logConfig.Build())

	address := fmt.Sprintf("localhost:%d", *port)
	logger.Debug("listening", zap.String("address", address))
	lis, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	if *tls {
		if *certFile == "" {
			*certFile = data.Path("x509/server_cert.pem")
		}
		if *keyFile == "" {
			*keyFile = data.Path("x509/server_key.pem")
		}
		creds, err := credentials.NewServerTLSFromFile(*certFile, *keyFile)
		if err != nil {
			log.Fatalf("Failed to generate credentials: %v", err)
		}
		opts = []grpc.ServerOption{grpc.Creds(creds)}
	}
	var auth *server.Auth
	if len(*basicAuth) > 0 {
		basicAuthSplit := strings.SplitN(*basicAuth, ":", 2)
		if len(basicAuthSplit) != 2 {
			panic("wrong basicAuth format")
		}
		auth = server.NewAuth(logger, basicAuthSplit[0], gcred.Secret(basicAuthSplit[1]))
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
	err = grpcServer.Serve(lis)
	panic(err)
}
