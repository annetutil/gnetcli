## Complex examples

```go
package main

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/annutil/gnetcli/pkg/cmd"
	"github.com/annutil/gnetcli/pkg/credentials"
	"github.com/annutil/gnetcli/pkg/device"
	"github.com/annutil/gnetcli/pkg/device/huawei"
	"github.com/annutil/gnetcli/pkg/streamer/ssh"
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
		credentials.WithSSHAgent(),
		credentials.WithLogger(logger),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	connector := ssh.NewStreamer(host, creds, ssh.WithLogger(logger))
	dev := huawei.NewDevice(connector)
	err := dev.Connect(ctx)

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
```
