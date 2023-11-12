A program which execute `display interfaces` and return output, error and exit status.

```go
package main

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/annetutil/gnetcli/pkg/cmd"
	dcreds "github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/device/huawei"
	"github.com/annetutil/gnetcli/pkg/streamer/ssh"
)

func main() {
	host := "somehost"
	password := "mypassword"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	logger := zap.Must(zap.NewDevelopmentConfig().Build())

	creds := dcreds.NewSimpleCredentials(
		dcreds.WithUsername(dcreds.GetLogin()),
		dcreds.WithSSHAgent(), // try pubkey auth using agent
		dcreds.WithPassword(dcreds.Secret(password)), // and password
		dcreds.WithLogger(logger),
	)
	connector := ssh.NewStreamer(host, creds, ssh.WithLogger(logger))
	dev := huawei.NewDevice(connector) // huawei CLI upon SSH
	err := dev.Connect(ctx)            // connection happens here
	if err != nil{
		panic(err)
    }
	defer dev.Close()
	res, _ := dev.Execute(cmd.NewCmd("display interfaces"))
	if res.Status() == 0 {
		fmt.Printf("Result: %s\n", res.Output())
	} else {
		fmt.Printf("Error: %s\nStatus: %d\n", res.Status(), res.Error())
	}
}
```
