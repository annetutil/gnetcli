package main

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/device/huawei"
	"github.com/annetutil/gnetcli/pkg/streamer/ssh"
)

func main() {
	host := "somehost"
	changeUser := "target_login"
	newPass := "newpassword"
	logConfig := zap.NewDevelopmentConfig()
	logger := zap.Must(logConfig.Build())

	creds := credentials.NewSimpleCredentials(
		credentials.WithUsername(credentials.GetLogin()),
		credentials.WithPassword(credentials.Secret("mypassword")),
		credentials.WithSSHAgentSocket(credentials.GetDefaultAgentSocket()),
		credentials.WithLogger(logger),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	connector := ssh.NewStreamer([]ssh.Endpoint{ssh.NewEndpoint(host)}, creds, ssh.WithLogger(logger))
	dev := huawei.NewDevice(connector)
	err := dev.Connect(ctx)
	if err != nil {
		logger.Fatal("connect error", zap.Error(err))
	}

	_, err = dev.Execute(cmd.NewCmd("system-view"))
	if err != nil {
		logger.Fatal("system-view error", zap.Error(err))
	}
	_, _ = dev.Execute(cmd.NewCmd("aaa"))
	_, _ = dev.Execute(cmd.NewCmd("local-user "+changeUser+" password",
		cmd.WithAnswers(
			cmd.NewAnswer("Enter Password:", newPass),
			cmd.NewAnswer("Confirm Password:", newPass),
		),
	))
	_, _ = dev.Execute(cmd.NewCmd("commit"))
}
