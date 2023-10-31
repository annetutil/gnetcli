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
	"github.com/annetutil/gnetcli/pkg/device/genericcli"
	"github.com/annetutil/gnetcli/pkg/device/huawei"
	"github.com/annetutil/gnetcli/pkg/device/juniper"
	"github.com/annetutil/gnetcli/pkg/streamer"
	"github.com/annetutil/gnetcli/pkg/streamer/ssh"
)

var devMapping = map[string]func(connector streamer.Connector, opts ...genericcli.GenericDeviceOption) genericcli.GenericDevice{
	"cisco":   cisco.NewDevice,
	"huawei":  huawei.NewDevice,
	"juniper": juniper.NewDevice,
}

func main() {
	host := flag.String("host", "", "host")
	login := flag.String("login", "", "login")
	devtype := flag.String("devtype", "", "devtype")
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
	devFab, ok := devMapping[*devtype]
	if !ok {
		panic(fmt.Sprintf("unknown devtype %s", *devtype))
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
	deva := devFab(connector)
	dev = &deva
	err := dev.Connect(ctx)
	if err != nil {
		panic(err)
	}

	res, err := dev.Execute(cmd.NewCmd(*command))
	if err != nil {
		logger.Fatal("error", zap.Error(err))
	}
	fmt.Printf("output: %v", string(res.Output()))
}
