package main

import (
	"flag"
	"fmt"
	"log"
	"net"

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
	certFile := flag.String("cert_file", "", "The TLS cert file")
	keyFile := flag.String("key_file", "", "The TLS key file")
	login := flag.String("login", "", "Authorization login")
	password := flag.String("password", "", "Authorization password")
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
	if len(*login) > 0 && len(*password) > 0 {
		auth = server.NewAuth(logger, *login, gcred.Secret(*password))
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

	creds := server.BuildCreds("", "", logger)
	s := server.New(
		server.WithLogger(logger),
		server.WithCredentials(creds),
	)
	pb.RegisterGnetcliServer(grpcServer, s)
	reflection.Register(grpcServer)
	err = grpcServer.Serve(lis)
	panic(err)
}
