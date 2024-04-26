package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"go.uber.org/zap"

	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/device/pc"
	"github.com/annetutil/gnetcli/pkg/streamer/ssh"
)

func main() {
	host := flag.String("host", "", "host")
	login := flag.String("login", "", "login")
	password := flag.String("password", "", "password")
	command := flag.String("command", "", "command")
	debug := flag.Bool("debug", false, "set debug log level")
	flag.Parse()
	if len(*host) == 0 {
		panic("empty host")
	}
	if len(*command) == 0 {
		panic("empty command")
	}
	if login == nil {
		newLogin := credentials.GetLogin()
		login = &newLogin
	}
	logConfig := zap.NewProductionConfig()
	if *debug {
		logConfig = zap.NewDevelopmentConfig()
	}

	logger := zap.Must(logConfig.Build())
	b, _ := os.ReadFile("~/.ssh/id_rsa")
	creds := credentials.NewSimpleCredentials(
		credentials.WithUsername(*login),
		credentials.WithPassword(credentials.Secret(*password)),
		//credentials.WithSSHAgent(),
		credentials.WithPrivateKey(b),
		credentials.WithLogger(logger),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	connector := ssh.NewStreamer(ssh.NewEndpoint(*host), creds, ssh.WithLogger(logger))
	dev := pc.NewDevice(connector)
	err := dev.Connect(ctx)
	if err != nil {
		panic(err)
	}

	res, err := dev.Execute(cmd.NewCmd(*command, cmd.WithForwarding(true)))
	if err != nil {
		logger.Fatal("error", zap.Error(err))
	}
	fmt.Printf("output: %v", string(res.Output()))
}
