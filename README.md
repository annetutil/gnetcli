Gnetcli
======
The ultimate solution for CLI automation in Golang. It provides a universal way to execute arbitrary commands using a CLI, eliminating the need for screen scraping with expect.
The project consist of go-library, GRPC server and CLI tool. It is typically used for automating network equipment such as Cisco, Juniper, Huawei, etc.

## Feature Overview:
* **Execute commands instead of just reading and writing.**
* **Pager, questions and error handling are supported.**  
  Describe CLI interface in a few expressions and get full power of the project.
* **The project supports several network vendors, including Huawei, Juniper, Cisco, and RouterOS.**
* **Netconf is supported.**  
  Exec netconf in same manner as text command to simplify automation workflow.
* **SSH tunneling is supported.**
* **Clean output**  
  Evaluation of terminal control codes and removal of echoes.
* **[CLI](https://annetutil.github.io/gnetcli/basic_usage_cli/) and [GRPC-server](https://annetutil.github.io/gnetcli/basic_usage_server/) for interacting with non-Go projects and other automations**.

Documentation available [here](https://annetutil.github.io/gnetcli/).

## Quick Start
### Go-library

Installation in go project:

```bash
go get -u github.com/annetutil/gnetcli
```

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
		dcreds.WithSSHAgentSocket(dcreds.GetDefaultAgentSocket()), // try pubkey auth using agent
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

### CLI

```shell
go install github.com/annetutil/gnetcli/cmd/cli@latest
cli -hostname myhost -devtype huawei -debug -command $'dis clock\ndis ver0' -password $password -json
```

```json
[
  {
    "output": "2023-10-29 10:00:00\nSunday\nTime Zone(UTC) : UTC\n",
    "error": "",
    "status": 0,
    "cmd": "dis clock"
  },
  {
    "output": "",
    "error": "              ^\nError: Unrecognized command found at '^' position.\n",
    "status": 1,
    "cmd": "dis ver0"
  }
]
```

### GRPC-server
Install and start the server:
```shell
go install github.com/annetutil/gnetcli/cmd/gnetcli_server@latest
server -debug -basic-auth mylogin:mysecret
```

Exec a command on a device using GRPC 
```shell
TOKEN=$(echo -n "$LOGIN:$PASSWORD" | base64)
grpcurl -H "Authorization: Basic $TOKEN" -plaintext -d '{"host": "hostname", "cmd": "dis clock", "host_params": {"device": "huawei", "credentials": {"login": "test", "password": "test"}}, "string_result": true}' localhost:50051 gnetcli.Gnetcli.Exec
```

## Start GRPC-server via docker
Clone the repository, build the image and run the container:
```shell
git clone https://github.com/annetutil/gnetcli.git
cd gnetcli
docker build -f image/Dockerfile -t gnetcli_server .
docker run -p 50051:50051 gnetcli_server
```