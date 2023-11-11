package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/annetutil/gnetcli/internal/devconf"
	"github.com/annetutil/gnetcli/pkg/cmd"
	gcred "github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/device"
	"github.com/annetutil/gnetcli/pkg/device/genericcli"
	"github.com/annetutil/gnetcli/pkg/streamer/ssh"
)

func main() {
	var knownDevs []string
	deviceMaps := devconf.InitDefaultDeviceMapping(zap.NewNop())
	for dName := range deviceMaps {
		knownDevs = append(knownDevs, dName)
	}
	dt := strings.Join(knownDevs, ", ")
	hostname := flag.String("hostname", "", "Hostname")
	port := flag.Int("port", 22, "Port")
	command := flag.String("command", "", "Command")
	devType := flag.String("devtype", "", fmt.Sprintf("Device type from %s", dt))
	login := flag.String("login", "", "Login")
	password := flag.String("password", "", "Password")
	debug := flag.Bool("debug", false, "Set debug log level")
	jsonOut := flag.Bool("json", false, "Output in JSON")
	deviceFiles := flag.String("dev-conf", "", "Path to yaml with device types")
	flag.Parse()
	if len(*hostname) == 0 {
		panic("empty hostname")
	}
	if len(*command) == 0 {
		panic("empty command")
	}
	logConfig := zap.NewProductionConfig()
	if *debug {
		logConfig = zap.NewDevelopmentConfig()
	}
	logger := zap.Must(logConfig.Build())
	// reinit with proper logger
	deviceMaps = devconf.InitDefaultDeviceMapping(zap.NewNop())

	if len(*deviceFiles) > 0 {
		res, err := loadDevice(*deviceFiles)
		if err != nil {
			panic(err)
		}
		for name, devType := range res {
			_, ok := deviceMaps[name]
			if ok {
				panic(fmt.Errorf("dev %s duplicate", name))
			}
			logger.Debug("add device", zap.String("name", name))
			deviceMaps[name] = devconf.GenericCLIDevToDev(devType)
		}
	}

	commands := strings.Split(*command, "\n")
	creds := buildCreds(*login, *password, logger)
	sshOpts := []ssh.StreamerOption{ssh.WithLogger(logger)}
	if port != nil {
		sshOpts = append(sshOpts, ssh.WithPort(*port))
	}
	connector := ssh.NewStreamer(*hostname, creds, sshOpts...)
	devFn, ok := deviceMaps[*devType]
	if !ok {
		panic(fmt.Errorf("unknown device %s", *devType))
	}
	dev := devFn(connector)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := exec(ctx, dev, commands, logger)
	if err != nil {
		panic(err)
	}
	resOut := ""
	if *jsonOut {
		jsonResOut, err := formatJSON(commands, res)
		if err != nil {
			panic(err)
		}
		resOut = jsonResOut
	} else {
		textResOut, err := formatText(commands, res)
		if err != nil {
			panic(err)
		}
		resOut = textResOut
	}
	fmt.Println(resOut)
}

type cmdResJSON struct {
	Output string `json:"output"`
	Error  string `json:"error"`
	Status int    `json:"status"`
	Cmd    string `json:"cmd"`
}

type cmdResJSONs []cmdResJSON

func formatText(commands []string, inputs []cmd.CmdRes) (string, error) {
	var res []string
	for i, input := range inputs {
		res = append(res, fmt.Sprintf("cmd=%s output=%s status=%d error=%s\n", commands[i], input.Output(), input.Status(), input.Error()))
	}
	return strings.Join(res, "\n"), nil
}

func formatJSON(command []string, inputs []cmd.CmdRes) (string, error) {
	jRes := cmdResJSONs{}
	for i, input := range inputs {
		jItem := cmdResJSON{
			Output: string(input.Output()),
			Error:  string(input.Error()),
			Status: input.Status(),
			Cmd:    command[i],
		}
		jRes = append(jRes, jItem)
	}
	res, err := json.Marshal(jRes)
	return string(res), err
}

func buildCreds(login, password string, logger *zap.Logger) gcred.Credentials {
	if len(login) == 0 {
		newLogin := gcred.GetLogin()
		login = newLogin
	}

	opts := []gcred.CredentialsOption{
		gcred.WithUsername(login),
		gcred.WithSSHAgent(),
		gcred.WithLogger(logger),
	}
	if len(password) > 0 {
		opts = append(opts, gcred.WithPassword(gcred.Secret(password)))
	}
	creds := gcred.NewSimpleCredentials(opts...)
	return creds
}

func exec(ctx context.Context, dev device.Device, commands []string, logger *zap.Logger) ([]cmd.CmdRes, error) {
	err := dev.Connect(ctx)
	if err != nil {
		return nil, err
	}
	var res []cmd.CmdRes
	for _, cmdIter := range commands {
		cRes, err := dev.Execute(cmd.NewCmd(cmdIter))
		if err != nil {
			logger.Warn("error", zap.Error(err))
		}
		res = append(res, cRes)
	}
	return res, nil
}

func loadDevice(path string) (map[string]*genericcli.GenericCLI, error) {
	yamlFile, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	conf := devconf.DevConfs{}
	err = yaml.Unmarshal(yamlFile, &conf)
	if err != nil {
		return nil, err
	}
	res, err := conf.Make()
	if err != nil {
		return nil, err
	}
	return res, nil
}
