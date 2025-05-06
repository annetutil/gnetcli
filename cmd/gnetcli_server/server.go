package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	gateway "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"

	grpcmiddleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpczap "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
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
	logConfig := zap.NewProductionConfig()
	logger := zap.Must(logConfig.Build())
	cfg, err := server.LoadConf()
	if err != nil {
		logger.Panic("conf error", zap.Error(err))
	}
	// copy params from legacy
	if len(cfg.DevLogin) > 0 {
		cfg.DevAuth.Login = cfg.DevLogin
	}
	if len(cfg.DevPass) > 0 {
		cfg.DevAuth.Password = gcred.Secret(cfg.DevPass)
	}
	if cfg.DevUseAgent {
		cfg.DevAuth.UseAgent = cfg.DevUseAgent
	}
	var grpcListeners []net.Listener

	logConfig = zap.NewDevelopmentConfig()
	if cfg.Logging.Json {
		logConfig = zap.NewProductionConfig()
	}
	logConfig.Level = zap.NewAtomicLevelAt(cfg.Logging.Level)
	logger = zap.Must(logConfig.Build())

	if len(cfg.UnixSocket) > 0 {
		// log level and "init unix socket", "path" is used in gnetcli_adapter
		logger.Warn("init unix socket", zap.String("path", cfg.UnixSocket))
		unixSocketLn, err := newUnixSocket(cfg.UnixSocket)
		if err != nil {
			logger.Panic("unix socket error", zap.Error(err))
		}
		grpcListeners = append(grpcListeners, unixSocketLn)
	}
	var gatewayServer *http.Server
	if !cfg.DisableTcp {
		address := cfg.Listen
		if !strings.Contains(cfg.Listen, ":") { // just port
			address = net.JoinHostPort("127.0.0.1", address)
		}
		tcpSocketLn, err := newTcpSocket(address)
		if err != nil {
			logger.Panic("tcp socket error", zap.Error(err))
		}
		// log level and "init tcp socket", "address" is used in gnetcli_adapter
		logger.Warn("init tcp socket", zap.String("address", tcpSocketLn.Addr().String()))
		grpcListeners = append(grpcListeners, tcpSocketLn)
		if cfg.HttpListen != "" {
			logger.Warn("init http gateway socket", zap.String("address", cfg.HttpListen))
			mux := gateway.NewServeMux()
			pb.RegisterGnetcliHandlerFromEndpoint(context.Background(), mux, address, []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())})
			gatewayServer = &http.Server{Addr: cfg.HttpListen, Handler: mux}
		}
	}
	if len(grpcListeners) == 0 {
		logger.Panic("specify tcp or unix socket")
	}
	var opts []grpc.ServerOption
	if cfg.Tls {
		if cfg.CertFile == "" {
			cfg.CertFile = path("x509/server_cert.pem")
		}
		if cfg.KeyFile == "" {
			cfg.KeyFile = path("x509/server_key.pem")
		}
		creds, err := credentials.NewServerTLSFromFile(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			log.Fatalf("Failed to generate credentials: %v", err)
		}
		opts = []grpc.ServerOption{grpc.Creds(creds)}
	}
	var auth *server.Auth
	if len(cfg.BasicAuth) > 0 {
		login, secret := parseAuth(cfg.BasicAuth)
		logger.Info("using basic auth")
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
	if cfg.DefaultReadTimeout > 0 {
		serverOpts = append(serverOpts, server.WithDefaultReadTimeout(cfg.DefaultReadTimeout))
	}
	if cfg.DefaultCmdTimeout > 0 {
		serverOpts = append(serverOpts, server.WithDefaultCmdTimeout(cfg.DefaultCmdTimeout))
	}
	devAuthApp := server.NewAuthApp(cfg.DevAuth, logger)
	s, err := server.New(devAuthApp, cfg.DevConf, serverOpts...)
	if err != nil {
		logger.Panic("failed to load external device map. Check your config!", zap.Error(err))
	}
	pb.RegisterGnetcliServer(grpcServer, s)
	reflection.Register(grpcServer)
	ctx := context.Background()
	wg, wCtx := errgroup.WithContext(ctx)
	for _, listener := range grpcListeners {
		wListener := listener
		wg.Go(func() error {
			return grpcServer.Serve(wListener)
		})
		context.AfterFunc(ctx, func() {
			logger.Debug("close ", zap.Any("wListener", wListener))
			_ = wListener.Close()
		})
	}
	context.AfterFunc(wCtx, func() {
		grpcServer.Stop()
		if gatewayServer != nil {
			gatewayServer.Close()
		}
	})
	if gatewayServer != nil {
		wg.Go(func() error {
			return gatewayServer.ListenAndServe()
		})
	}
	wg.Go(func() error {
		err := WaitInterrupted(wCtx)
		logger.Debug("WaitInterrupted", zap.Error(err))
		return err
	})
	err = wg.Wait()
	if err != nil {
		panic(err)
	}
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

type Interrupted struct {
	os.Signal
}

func (m Interrupted) Error() string {
	return m.String()
}

func WaitInterrupted(ctx context.Context) error {
	ch := make(chan os.Signal, 1)

	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	select {
	case v := <-ch:
		return Interrupted{Signal: v}
	case <-ctx.Done():
		return ctx.Err()
	}
}
