A program which execute `display clock` and return output, error and exit status.

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
	res, _ := dev.Execute(cmd.NewCmd("display clock"))
	if res.Status() == 0 {
		fmt.Printf("Result: %s\n", res.Output())
	} else {
		fmt.Printf("Error: %s\nStatus: %d\n", res.Error(), res.Status())
	}
}
```

Produces the following output it command was executed successfully:

```text
Result: 2023-12-07 12:01:49
Thursday
Time Zone(UTC) : UTC
```

In case of error:

```text
Error:           ^
Error: Unrecognized command found at '^' position.
Status: 1
```
