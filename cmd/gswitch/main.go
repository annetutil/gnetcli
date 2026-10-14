package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/annetutil/gnetcli/pkg/gswitch"
	"github.com/annetutil/gnetcli/pkg/gswitch/emulator"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	debug := flag.Bool("debug", false, "Set debug log level")
	host := flag.String("host", "localhost", "Server host")
	sshPort := flag.Int("port", 2223, "SSH server port")
	telnetPort := flag.Int("telnet-port", 2223, "Telnet server port")
	enableTelnet := flag.Bool("enable-telnet", false, "Enable Telnet server")
	enableSSH := flag.Bool("enable-ssh", true, "Enable SSH server")
	username := flag.String("username", "cisco", "Username for authentication")
	password := flag.String("password", "cisco", "Password for authentication")
	connectionErrorProb := flag.Float64("connection-error-prob", 0.0, "Probability of connection error after accept (0.0-1.0)")
	authorizedKeysFile := flag.String("authorized-keys", "", "OpenSSH authorized_keys file; enables key auth in addition to password")
	configFile := flag.String("config-file", "", "Initial Cisco-style running configuration; changes remain in memory")
	readyFile := flag.String("ready-file", "", "Write actual listener addresses as JSON when ready; remove on shutdown")
	commandDelay := flag.Duration("command-delay", 0, "Delay each CLI command (including session setup) for timeout tests")
	profileFile := flag.String("profile", "", "Declarative emulator YAML profile (opt-in)")
	scenarioFile := flag.String("scenario", "", "Scenario YAML for -profile")
	sshMode := flag.String("ssh-mode", "cli", "Profile SSH endpoint: cli or console")
	consoleUsername := flag.String("console-username", "", "Device console username; defaults to SSH username")
	consolePassword := flag.String("console-password", "", "Device console password; defaults to SSH password")
	controlPort := flag.Int("control-port", -1, "Local control API on 127.0.0.1; -1 disables, 0 selects a free port")
	controlToken := flag.String("control-token", "", "Bearer token for control API (at least 16 characters)")
	consolePort := flag.Int("console-port", -1, "Raw TCP console for -profile; -1 disables, 0 selects a free port")
	flag.Parse()
	if *sshMode != "cli" && *sshMode != "console" {
		return errors.New("-ssh-mode must be cli or console")
	}
	if *profileFile == "" && (*sshMode != "cli" || *consoleUsername != "" || *consolePassword != "" || *controlPort >= 0 || *controlToken != "") {
		return errors.New("SSH console and control options require -profile")
	}
	if *controlPort >= 0 && len(*controlToken) < 16 {
		return errors.New("-control-port requires -control-token with at least 16 characters")
	}
	if !*enableSSH && !*enableTelnet && *consolePort < 0 && *controlPort < 0 {
		return errors.New("at least one server (SSH, Telnet, console or control) must be enabled")
	}
	if *commandDelay < 0 {
		return errors.New("command-delay cannot be negative")
	}
	if *readyFile != "" {
		if err := os.Remove(*readyFile); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove stale ready-file: %w", err)
		}
	}
	if *profileFile == "" && (*scenarioFile != "" || *consolePort >= 0) {
		return errors.New("-scenario and -console-port require -profile")
	}
	if *profileFile != "" && (*enableTelnet || *configFile != "" || *commandDelay != 0) {
		return errors.New("-profile does not support legacy -enable-telnet, -config-file or -command-delay; use profile actions and raw console")
	}
	logConfig := zap.NewProductionConfig()
	if *debug {
		logConfig = zap.NewDevelopmentConfig()
	}
	logger := zap.Must(logConfig.Build())

	config := gswitch.NewRunningConfig()
	if *configFile != "" {
		data, err := os.ReadFile(*configFile)
		if err != nil {
			return fmt.Errorf("read config-file: %w", err)
		}
		if err := config.Load(string(data)); err != nil {
			return fmt.Errorf("load config-file: %w", err)
		}
	}
	opts := gswitch.SSHServerOptions{Logger: logger, Username: *username, Password: *password,
		ConnectionErrorProb: *connectionErrorProb, Config: config, CommandDelay: *commandDelay}
	if *authorizedKeysFile != "" {
		keys, err := gswitch.LoadAuthorizedKeysFromFile(*authorizedKeysFile)
		if err != nil {
			return fmt.Errorf("authorized-keys: %w", err)
		}
		opts.AuthorizedKeys = keys
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var emulated *emulator.Device
	if *profileFile != "" {
		f, err := os.Open(*profileFile)
		if err != nil {
			return err
		}
		root, err := os.OpenRoot(filepath.Dir(*profileFile))
		if err != nil {
			f.Close()
			return err
		}
		profile, err := emulator.LoadProfile(f, root.FS())
		f.Close()
		root.Close()
		if err != nil {
			return fmt.Errorf("load profile: %w", err)
		}
		var scenario *emulator.Scenario
		if *scenarioFile != "" {
			f, err := os.Open(*scenarioFile)
			if err != nil {
				return err
			}
			root, err := os.OpenRoot(filepath.Dir(*scenarioFile))
			if err != nil {
				f.Close()
				return err
			}
			scenario, err = emulator.LoadScenario(f, root.FS())
			f.Close()
			root.Close()
			if err != nil {
				return fmt.Errorf("load scenario: %w", err)
			}
		}
		emulated, err = emulator.New(profile, emulator.Options{Username: fallback(*consoleUsername, *username), Password: fallback(*consolePassword, *password), Scenario: scenario})
		if err != nil {
			return err
		}
		defer emulated.Close()
		if *controlPort >= 0 {
			if _, err := emulated.ControlHandler(*controlToken); err != nil {
				return err
			}
		}
		opts.SSHSessionHandler = func(ctx context.Context, channel io.ReadWriteCloser, info gswitch.SSHSession) error {
			return serveEmulatedSSH(ctx, emulated, channel, info, *sshMode == "console")
		}
	}
	wg, wCtx := errgroup.WithContext(ctx)
	var sshListener, telnetListener, consoleListener, controlListener net.Listener
	addresses := make(map[string]string)
	if *enableSSH {
		var err error
		sshListener, err = net.Listen("tcp", net.JoinHostPort(*host, strconv.Itoa(*sshPort)))
		if err != nil {
			return fmt.Errorf("listen SSH: %w", err)
		}
		defer sshListener.Close()
		addresses["ssh"] = sshListener.Addr().String()
		logger.Warn("SSH server listening on", zap.String("addr", addresses["ssh"]))
	}
	if *enableTelnet {
		var err error
		telnetListener, err = net.Listen("tcp", net.JoinHostPort(*host, strconv.Itoa(*telnetPort)))
		if err != nil {
			return fmt.Errorf("listen Telnet: %w", err)
		}
		defer telnetListener.Close()
		addresses["telnet"] = telnetListener.Addr().String()
		logger.Warn("Telnet server listening on", zap.String("addr", addresses["telnet"]))
	}
	if *consolePort >= 0 {
		var err error
		consoleListener, err = net.Listen("tcp", net.JoinHostPort(*host, strconv.Itoa(*consolePort)))
		if err != nil {
			return fmt.Errorf("listen console: %w", err)
		}
		defer consoleListener.Close()
		addresses["console"] = consoleListener.Addr().String()
	}
	if *controlPort >= 0 {
		var err error
		controlListener, err = net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(*controlPort)))
		if err != nil {
			return fmt.Errorf("listen control: %w", err)
		}
		defer controlListener.Close()
		addresses["control"] = controlListener.Addr().String()
	}
	if emulated != nil {
		wg.Go(func() error { return emulated.Run(wCtx) })
	}
	if controlListener != nil {
		wg.Go(func() error { return emulated.ServeControl(wCtx, controlListener, *controlToken) })
	}
	if consoleListener != nil {
		wg.Go(func() error { return emulated.ServeConsole(wCtx, consoleListener, "console0") })
	}
	if *readyFile != "" {
		if err := writeReadyFile(*readyFile, addresses); err != nil {
			return fmt.Errorf("ready-file: %w", err)
		}
		defer os.Remove(*readyFile)
	}
	if sshListener != nil {
		wg.Go(func() error { return gswitch.ServeSSH(wCtx, sshListener, opts) })
	}
	if telnetListener != nil {
		wg.Go(func() error { return gswitch.ServeTelnet(wCtx, telnetListener, opts) })
	}
	err := wg.Wait()
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func writeReadyFile(path string, addresses map[string]string) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".gswitch-ready-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := json.NewEncoder(f).Encode(addresses); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
