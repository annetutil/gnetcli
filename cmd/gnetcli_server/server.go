package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	gateway "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"

	grpcmiddleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpczap "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"

	"github.com/annetutil/gnetcli/internal/listenermux"
	gcred "github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/models"
	"github.com/annetutil/gnetcli/pkg/server"
	pb "github.com/annetutil/gnetcli/pkg/server/proto"
)

type ExecErrorType string

const (
	ErrorTypeGeneric    ExecErrorType = "generic_error"
	ErrorTypeConnection ExecErrorType = "connection_error"
	ErrorTypeConnect    ExecErrorType = "connect_error"
	shutdownTimeout                   = 10 * time.Second
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

func connectionErrorUnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	resp, err := handler(ctx, req)
	return resp, connectionErrorInterceptor(err)
}

func connectionErrorStreamInterceptor(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	err := handler(srv, ss)
	return connectionErrorInterceptor(err)
}

func connectionErrorInterceptor(inErr error) error {
	if inErr == nil {
		return nil
	}
	_, ok := status.FromError(inErr)
	if ok {
		return inErr
	}

	msg := ErrorTypeGeneric
	reason := string(ErrorTypeGeneric)

	if strings.Contains(inErr.Error(), "failed to connect to host") {
		msg = ErrorTypeConnect
		reason = string(ErrorTypeConnection)
	}

	st := status.New(codes.Internal, string(msg))
	rv, _ := st.WithDetails(
		&errdetails.ErrorInfo{
			Reason:   reason,
			Metadata: map[string]string{"err": inErr.Error()},
		},
	)
	return rv.Err()
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
		unixSocketLn, err := newUnixSocket(cfg.UnixSocket)
		if err != nil {
			logger.Panic("unix socket error", zap.Error(err))
		}
		// log level and "init unix socket", "path" is used in GnetcliStarter
		// also should be placed after the listener creation to avoid race condition
		// when GnetcliStarter client tries to connect to a socket that does not exist yet
		logger.Warn("init unix socket", zap.String("path", cfg.UnixSocket))
		defer unixSocketLn.Close()
		grpcListeners = append(grpcListeners, unixSocketLn)
	}
	var gatewayServer *http.Server
	var gatewayListener net.Listener
	var sharedMux *listenermux.Mux
	var gatewayEndpoint string
	if cfg.DisableTcp && cfg.HttpListen != "" {
		logger.Panic("http_port requires TCP to be enabled")
	}
	if !cfg.DisableTcp {
		address := listenAddress(cfg.Listen)
		tcpSocketLn, err := newTcpSocket(address)
		if err != nil {
			logger.Panic("tcp socket error", zap.Error(err))
		}
		defer tcpSocketLn.Close()
		// Keep this message/field for GnetcliStarter, including ephemeral ports.
		logger.Warn("init tcp socket", zap.String("address", tcpSocketLn.Addr().String()))
		grpcListener := tcpSocketLn
		if cfg.HttpListen != "" {
			httpAddress := listenAddress(cfg.HttpListen)
			if httpAddress == address {
				sharedMux, err = listenermux.New(tcpSocketLn)
				if err != nil {
					logger.Panic("shared listener error", zap.Error(err))
				}
				defer sharedMux.Close()
				grpcListener = sharedMux.GRPCListener()
				gatewayListener = sharedMux.HTTPListener()
			} else {
				gatewayListener, err = newTcpSocket(httpAddress)
				if err != nil {
					logger.Panic("http socket error", zap.Error(err))
				}
			}
			defer gatewayListener.Close()
			logger.Warn("init http gateway socket", zap.String("address", gatewayListener.Addr().String()))
			// Dial the allocated port, never the configured ":0" or a wildcard.
			endpoint := tcpSocketLn.Addr().(*net.TCPAddr)
			ip := endpoint.IP
			if ip.IsUnspecified() {
				if ip.To4() != nil {
					ip = net.IPv4(127, 0, 0, 1)
				} else {
					ip = net.IPv6loopback
				}
			}
			gatewayEndpoint = net.JoinHostPort(ip.String(), fmt.Sprint(endpoint.Port))
		}
		grpcListeners = append(grpcListeners, grpcListener)
	}
	if len(grpcListeners) == 0 {
		logger.Panic("specify tcp or unix socket")
	}
	var opts []grpc.ServerOption
	var gatewayCredentials credentials.TransportCredentials = insecure.NewCredentials()
	if cfg.Tls {
		if cfg.CertFile == "" {
			cfg.CertFile = path("x509/server_cert.pem")
		}
		if cfg.KeyFile == "" {
			cfg.KeyFile = path("x509/server_key.pem")
		}
		certificate, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			logger.Panic("load TLS key pair", zap.Error(err))
		}
		opts = []grpc.ServerOption{grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12,
		}))}
		if gatewayListener != nil {
			// The gateway connects back to this server. Trust its configured
			// certificate, but still verify the certificate name and lifetime.
			leaf, err := x509.ParseCertificate(certificate.Certificate[0])
			if err != nil {
				logger.Panic("parse TLS certificate", zap.Error(err))
			}
			roots := x509.NewCertPool()
			roots.AddCert(leaf)
			name := ""
			if len(leaf.DNSNames) > 0 {
				name = leaf.DNSNames[0]
				if strings.HasPrefix(name, "*.") {
					name = "localhost" + name[1:]
				}
			} else if len(leaf.IPAddresses) > 0 {
				name = leaf.IPAddresses[0].String()
			}
			gatewayCredentials = credentials.NewTLS(&tls.Config{RootCAs: roots, ServerName: name, MinVersion: tls.VersionTLS12})
		}
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
		// Bound incomplete HTTP/2/TLS handshakes as well as mux sniffing.
		// Otherwise native gRPC shutdown can wait for its 120s default.
		grpc.ConnectionTimeout(5*time.Second),
		grpc.UnaryInterceptor(grpcmiddleware.ChainUnaryServer(
			grpczap.UnaryServerInterceptor(logger),
			auth.AuthenticateUnary,
			connectionErrorUnaryInterceptor,
		)),
		grpc.StreamInterceptor(grpcmiddleware.ChainStreamServer(
			grpczap.StreamServerInterceptor(logger),
			auth.AuthenticateStream,
			connectionErrorStreamInterceptor,
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
	if cfg.ModelsDir != "" {
		runner, err := models.New(cfg.ModelsDir)
		if err != nil {
			logger.Fatal("failed to load models directory", zap.Error(err))
		}
		serverOpts = append(serverOpts, server.WithModelRunner(runner))
	}
	devAuthApp := server.NewAuthApp(cfg.DevAuth, logger)
	s, err := server.New(devAuthApp, cfg.DevConf, serverOpts...)
	if err != nil {
		logger.Panic("failed to load external device map. Check your config!", zap.Error(err))
	}
	if gatewayListener != nil {
		conn, err := grpc.DialContext(context.Background(), gatewayEndpoint, grpc.WithTransportCredentials(gatewayCredentials))
		if err != nil {
			logger.Panic("gateway dial error", zap.Error(err))
		}
		defer conn.Close()
		mux := gateway.NewServeMux()
		if err := pb.RegisterGnetcliHandler(context.Background(), mux, conn); err != nil {
			logger.Panic("gateway registration error", zap.Error(err))
		}
		gatewayServer = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
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
	}
	shutdownDone := make(chan struct{})
	context.AfterFunc(wCtx, func() {
		defer close(shutdownDone)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		if gatewayServer != nil {
			if err := gatewayServer.Shutdown(shutdownCtx); err != nil {
				logger.Error("http gateway graceful shutdown failed", zap.Error(err))
				_ = gatewayServer.Close()
			}
		}

		if sharedMux != nil {
			_ = sharedMux.Close()
		}

		grpcStopped := make(chan struct{})
		go func() {
			grpcServer.GracefulStop()
			close(grpcStopped)
		}()
		select {
		case <-grpcStopped:
			logger.Debug("grpc server stopped gracefully")
		case <-shutdownCtx.Done():
			logger.Warn("grpc graceful shutdown timed out")
			grpcServer.Stop()
		}
	})
	if gatewayServer != nil {
		wg.Go(func() error {
			return gatewayServer.Serve(gatewayListener)
		})
	}
	if sharedMux != nil {
		wg.Go(func() error { return sharedMux.Serve(context.Background()) })
	}
	wg.Go(func() error {
		err := WaitInterrupted(wCtx)
		logger.Debug("WaitInterrupted", zap.Error(err))
		return err
	})
	err = wg.Wait()
	<-shutdownDone
	if err != nil && !isExpectedShutdown(err) {
		panic(err)
	}
	logger.Info("server stopped", zap.Error(err))
}

func isExpectedShutdown(err error) bool {
	var interrupted Interrupted
	return errors.As(err, &interrupted) ||
		errors.Is(err, grpc.ErrServerStopped) ||
		errors.Is(err, http.ErrServerClosed) ||
		errors.Is(err, net.ErrClosed)
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

func listenAddress(address string) string {
	if !strings.Contains(address, ":") {
		return net.JoinHostPort("127.0.0.1", address)
	}
	return address
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
	defer signal.Stop(ch)
	select {
	case v := <-ch:
		return Interrupted{Signal: v}
	case <-ctx.Done():
		return ctx.Err()
	}
}
