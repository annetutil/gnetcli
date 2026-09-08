package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/streamer/console"
	"go.uber.org/zap"
)

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdout, os.Stderr))
}

func runCLI(args []string, stdout, stderr io.Writer) int {
	cfg, err := parseConfig(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "gconsolecheck: %v\n", err)
		return 1
	}

	logger := zap.NewNop()
	if cfg.debug {
		logConfig := zap.NewDevelopmentConfig()
		logConfig.OutputPaths = []string{"stderr"}
		logConfig.ErrorOutputPaths = []string{"stderr"}
		logger, err = logConfig.Build()
		if err != nil {
			fmt.Fprintf(stderr, "gconsolecheck: create logger: %v\n", err)
			return 1
		}
	}
	defer func() { _ = logger.Sync() }()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	factory, discoverPorts, closeFactory, err := makeConserverFactory(cfg, logger)
	if err != nil {
		fmt.Fprintf(stderr, "gconsolecheck: configure jump host: %v\n", err)
		return 1
	}
	defer closeFactory()
	started := time.Now()
	if seedIsUsed(cfg.scenarios) {
		fmt.Fprintf(stdout, "SEED seed=%d\n", cfg.seed)
	}
	discoveryFailed := false
	if scenarioSelected(cfg.scenarios, "test_discovery_all_ports") {
		if err := runDiscoveryAllPorts(ctx, cfg, factory, discoverPorts, stdout); err != nil {
			fmt.Fprintf(stdout, "DISCOVERY_ALL_PORTS FAIL error=%v\n", err)
			discoveryFailed = true
		}
	}
	pairCfg := cfg
	pairCfg.scenarios = pairScenarios(cfg.scenarios)
	var results []pairResult
	if len(pairCfg.scenarios) > 0 {
		results = runAllPairs(ctx, pairCfg, factory, stdout)
	}

	passed := 0
	var verified uint64
	for _, result := range results {
		verified += result.bytesVerified
		if result.passed {
			passed++
		}
	}
	failed := len(results) - passed
	interrupted := ctx.Err() != nil
	fmt.Fprintf(stdout, "SUMMARY pairs=%d passed=%d failed=%d bytes=%d duration=%s interrupted=%t\n",
		len(results), passed, failed, verified, time.Since(started).Round(time.Millisecond), interrupted)
	if interrupted {
		return 130
	}
	if failed > 0 || discoveryFailed {
		return 1
	}
	return 0
}

func scenarioSelected(scenarios []string, target string) bool {
	for _, scenario := range scenarios {
		if scenario == target {
			return true
		}
	}
	return false
}

func pairScenarios(scenarios []string) []string {
	result := make([]string, 0, len(scenarios))
	for _, scenario := range scenarios {
		if scenario != "test_discovery_all_ports" {
			result = append(result, scenario)
		}
	}
	return result
}

func seedIsUsed(scenarios []string) bool {
	for _, scenario := range scenarios {
		if scenario == "test_one_way" || scenario == "test_random_soak" || scenario == "test_random_soak_ascii" || scenario == "test_discovery" || scenario == "test_discovery_all_ports" {
			return true
		}
	}
	return false
}

type portsDiscovery func(context.Context) (console.CommandsInfoResult, error)

func makeConserverFactory(cfg config, logger *zap.Logger) (sessionFactory, portsDiscovery, func(), error) {
	var creds credentials.Credentials
	if cfg.username != "" {
		creds = credentials.NewSimpleCredentials(credentials.WithUsername(cfg.username))
	}
	jumpTunnel, err := makeJumpTunnel(cfg, logger)
	if err != nil {
		return nil, nil, func() {}, err
	}
	closeFactory := func() {
		if jumpTunnel != nil {
			jumpTunnel.Close()
		}
	}
	factory := func(ctx context.Context, portName string) (dataSession, error) {
		if jumpTunnel != nil {
			if err := jumpTunnel.EnsureConnected(ctx, cfg.timeout); err != nil {
				return nil, err
			}
		}
		session, err := connectConserver(ctx, cfg, creds, portName, cfg.ssl, jumpTunnel, logger)
		if err == nil || cfg.ssl || !isEncryptionRequired(err) {
			return session, err
		}
		logger.Debug("conserver requires encryption, retrying with SSL", zap.String("console_port", portName))
		return connectConserver(ctx, cfg, creds, portName, true, jumpTunnel, logger)
	}
	discover := func(ctx context.Context) (console.CommandsInfoResult, error) {
		if jumpTunnel != nil {
			if err := jumpTunnel.EnsureConnected(ctx, cfg.timeout); err != nil {
				return nil, err
			}
		}
		ports, err := discoverConserverPorts(ctx, cfg, creds, cfg.ssl, jumpTunnel, logger)
		if err == nil || cfg.ssl || !isEncryptionRequired(err) {
			return ports, err
		}
		return discoverConserverPorts(ctx, cfg, creds, true, jumpTunnel, logger)
	}
	return factory, discover, closeFactory, nil
}

func discoverConserverPorts(ctx context.Context, cfg config, creds credentials.Credentials, useSSL bool, jumpTunnel *managedTunnel, logger *zap.Logger) (console.CommandsInfoResult, error) {
	discoveryLogger := logger.With(zap.String("console_port", "discovery"))
	options := []console.StreamerOption{
		console.WithPort(cfg.port),
		console.WithSetupReadTimeout(cfg.readTimeout),
		console.WithLogger(discoveryLogger),
	}
	if useSSL {
		options = append(options, console.WithHackedSSL())
	}
	if jumpTunnel != nil {
		options = append(options, console.WithSSHTunnelConn(jumpTunnel.Tunnel()))
	}
	stream := console.NewStreamer(cfg.host, "", creds, nil, options...)
	stream.SetReadTimeout(cfg.readTimeout)
	defer stream.Close()
	return stream.DiscoveryAllPorts(ctx)
}

func connectConserver(ctx context.Context, cfg config, creds credentials.Credentials, portName string, useSSL bool, jumpTunnel *managedTunnel, logger *zap.Logger) (dataSession, error) {
	sessionCtx, cancel := context.WithCancel(ctx)
	portLogger := logger.With(zap.String("console_port", portName))
	options := []console.StreamerOption{
		console.WithPort(cfg.port),
		console.WithSpeed(cfg.speed),
		console.WithSetupReadTimeout(cfg.readTimeout),
		console.WithLogger(portLogger),
	}
	if useSSL {
		options = append(options, console.WithHackedSSL())
	}
	if jumpTunnel != nil {
		options = append(options, console.WithSSHTunnelConn(jumpTunnel.Tunnel()))
	}
	stream := console.NewStreamer(cfg.host, portName, creds, nil, options...)
	stream.SetReadTimeout(cfg.readTimeout)
	timer := time.AfterFunc(cfg.timeout, func() {
		cancel()
		stream.Close()
	})
	if err := stream.Init(sessionCtx); err != nil {
		timer.Stop()
		cancel()
		stream.Close()
		return nil, err
	}
	if !timer.Stop() || sessionCtx.Err() != nil {
		cancel()
		stream.Close()
		return nil, fmt.Errorf("connection timeout: %w", context.DeadlineExceeded)
	}
	return newConserverDataSession(stream, cancel), nil
}

func isEncryptionRequired(err error) bool {
	return err != nil && strings.Contains(err.Error(), "encryption required")
}
