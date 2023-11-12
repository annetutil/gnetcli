# Welcome to Gnetclis

The ultimate solution for CLI automation in Golang. It provides a universal way to execute arbitrary commands using a CLI, eliminating the need for screen scraping with expect.
The project consist of go-library, GRPC-server and CLI-tool. It is typically used for automating network equipment such as Cisco, Juniper, Huawei, etc.

Documentation available [here](https://annetutil.github.io/gnetcli/).


Install:
```shell
go get -u github.com/annetutil/gnetcli
```

Short example:

```go
func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	logger := zap.Must(zap.NewDevelopmentConfig().Build())
	creds := dcreds.NewSimpleCredentials(
		credentials.WithUsername(dcreds.GetLogin()),
		credentials.WithPassword(dcreds.Secret("mypassword")), // and password
	)
	connector := ssh.NewStreamer("myhost.domain", creds, ssh.WithLogger(logger))
	dev := huawei.NewDevice(connector) // huawei CLI upon SSH
	err := dev.Connect(ctx)            // connection happens here
	if err != nil{
		panic(err)
    }
	defer dev.Close()
	res, _ := dev.Execute(cmd.NewCmd("display interfaces"))
	fmt.Printf("Status: %d\nError: %s\nStatus: %d\n", res.Status(), res.Output(), res.Error())
}
```
