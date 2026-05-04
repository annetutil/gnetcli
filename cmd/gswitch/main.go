package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/annetutil/gnetcli/pkg/gswitch"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

func main() {
	debug := flag.Bool("debug", false, "Set debug log level")
	host := flag.String("host", "localhost", "Server host")
	sshPort := flag.Int("port", 2223, "SSH server port")
	telnetPort := flag.Int("telnet-port", 2223, "Telnet server port")
	enableTelnet := flag.Bool("enable-telnet", false, "Enable Telnet server")
	enableSSH := flag.Bool("enable-ssh", true, "Enable SSH server")
	username := flag.String("username", "cisco", "Username for authentication")
	password := flag.String("password", "cisco", "Password for authentication")
	connectionErrorProb := flag.Float64("connection-error-prob", 0.0, "Probability of connection error after accept (0.0-1.0)")
	authorizedKeysFile := flag.String("authorized-keys", "", "If set, OpenSSH authorized_keys file path; clients may authenticate with a listed public key (in addition to password)")
	flag.Parse()

	logConfig := zap.NewProductionConfig()
	if *debug {
		logConfig = zap.NewDevelopmentConfig()
	}
	logger := zap.Must(logConfig.Build())

	ctx := context.Background()
	wg, wCtx := errgroup.WithContext(ctx)

	opts := gswitch.SSHServerOptions{
		Logger:              logger,
		Username:            *username,
		Password:            *password,
		ConnectionErrorProb: *connectionErrorProb,
	}
	if len(*authorizedKeysFile) > 0 {
		keys, err := gswitch.LoadAuthorizedKeysFromFile(*authorizedKeysFile)
		if err != nil {
			log.Fatal("authorized-keys: ", err)
		}
		opts.AuthorizedKeys = keys
	}

	if *enableSSH {
		sshAddr := fmt.Sprintf("%s:%d", *host, *sshPort)
		sshListener, err := net.Listen("tcp", sshAddr)
		if err != nil {
			log.Fatal("Failed to listen on SSH ", sshAddr, ": ", err)
		}

		logger.Warn("SSH server listening on", zap.String("addr", sshAddr))

		wg.Go(func() error {
			return gswitch.ServeSSH(wCtx, sshListener, opts)
		})
	}

	if *enableTelnet {
		telnetAddr := fmt.Sprintf("%s:%d", *host, *telnetPort)
		telnetListener, err := net.Listen("tcp", telnetAddr)
		if err != nil {
			log.Fatal("Failed to listen on Telnet ", telnetAddr, ": ", err)
		}

		logger.Warn("Telnet server listening on", zap.String("addr", telnetAddr))

		wg.Go(func() error {
			return gswitch.ServeTelnet(wCtx, telnetListener, opts)
		})
	}

	if !*enableSSH && !*enableTelnet {
		logger.Fatal("At least one server (SSH or Telnet) must be enabled")
	}

	err := wg.Wait()
	if err != nil {
		logger.Fatal("server error", zap.Error(err))
	}
}
