package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/device"
	"github.com/annetutil/gnetcli/pkg/device/cisco"
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

	creds := credentials.NewSimpleCredentials(
		credentials.WithUsername(*login),
		credentials.WithPassword(credentials.Secret(*password)),
		credentials.WithSSHAgent(),
		credentials.WithLogger(logger),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	connector := ssh.NewStreamer(*host, creds, ssh.WithLogger(logger))
	var dev device.Device
	deva := cisco.NewDevice(connector)
	dev = &deva
	err := dev.Connect(ctx)
	if err != nil {
		panic(err)
	}

	res, err := dev.Execute(cmd.NewCmd(*command))
	if res.Status() == 0 {
		fmt.Printf("Result: %s\n", res.Output())
	} else {
		fmt.Printf("Error: %s\nStatus: %d\n", res.Error(), res.Status())
	}
}
