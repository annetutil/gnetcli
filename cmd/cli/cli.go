package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/annetutil/gnetcli/pkg/testutils"
	"strings"
	"testing"
	"time"

	"github.com/annetutil/gnetcli/pkg/cmd"
	gcred "github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/devconf"
	"github.com/annetutil/gnetcli/pkg/device"
	"github.com/annetutil/gnetcli/pkg/server"
	"github.com/annetutil/gnetcli/pkg/streamer/ssh"
	"go.uber.org/zap"
)

type questionFlags []string

func (m *questionFlags) String() string {
	return strings.Join(*m, ",")
}

func (m *questionFlags) Set(value string) error {
	*m = append(*m, strings.TrimSpace(value))
	return nil
}

func parseQuestions(input []string) []cmd.CmdOption {
	var res []cmd.CmdOption
	for _, question := range input {
		splitRes := strings.SplitN(question, ":::", 2)
		if len(splitRes) == 2 {
			res = append(res, cmd.WithAddAnswers(cmd.NewAnswer(splitRes[0], splitRes[1])))
		}
	}
	return res
}

func main() {
	var question questionFlags
	dt := devconf.GetEmbeddedDeviceTypeList()
	hostname := flag.String("hostname", "", "Hostname")
	port := flag.Int("port", 22, "Port")
	command := flag.String("command", "", "Command")
	flag.Var(&question, "question", "Question")
	devType := flag.String("devtype", "", fmt.Sprintf("Device type from dev-conf file or from predifined: %s", dt))
	login := flag.String("login", "", "Login")
	password := flag.String("password", "", "Password")
	useSSHConfig := flag.Bool("use-ssh-config", false, "Use default ssh config")
	sshConfigPassphrase := flag.String("ssh-config-passphrase", "", "Passphrase for ssh config's identity file")
	debug := flag.Bool("debug", false, "Set debug log level")
	test := flag.Bool("test", false, "Run tests on config")
	jsonOut := flag.Bool("json", false, "Output in JSON")
	deviceFiles := flag.String("dev-conf", "", "Path to yaml with device types")
	flag.Parse()
	logConfig := zap.NewProductionConfig()
	if *debug {
		logConfig = zap.NewDevelopmentConfig()
	}
	logger := zap.Must(logConfig.Build())
	// reinit with proper logger
	deviceMaps := devconf.InitDeviceMapping(zap.NewNop(), *deviceFiles)

	if *test && len(*deviceFiles) > 0 {
		makeExternalDeviceConfigTests(deviceFiles)
	}

	if len(*hostname) == 0 {
		panic("empty hostname")
	}
	if len(*command) == 0 {
		panic("empty command")
	}
	commands := strings.Split(*command, "\n")
	creds, err := buildCreds(*login, *password, *hostname, *sshConfigPassphrase, *useSSHConfig, logger)
	if err != nil {
		panic(err)
	}
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
	cmdQuestion := parseQuestions(question)
	res, err := exec(ctx, dev, commands, cmdQuestion, logger)
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

func makeExternalDeviceConfigTests(deviceFiles *string) {
	conf, err := devconf.LoadExternalDeviceConfig(*deviceFiles)
	if err != nil {
		panic(err)
	}
	var tests []testing.InternalTest
	for _, vendorConf := range conf.Devices {
		for i, errExpTestData := range vendorConf.Tests.ErrorExpressionVariants {
			tests = append(tests, testing.InternalTest{fmt.Sprintf("vendor_%s_err_%d", vendorConf.Name, i), func(t *testing.T) {
				testutils.ExprTester(t, [][]byte{[]byte(errExpTestData)}, vendorConf.ErrorExpression)
			}})
		}
		for i, errExpTestData := range vendorConf.Tests.PromptExpressionVariants {
			tests = append(tests, testing.InternalTest{fmt.Sprintf("vendor_%s_prompt_%d", vendorConf.Name, i), func(t *testing.T) {
				testutils.ExprTester(t, [][]byte{[]byte(errExpTestData)}, vendorConf.PromptExpression)
			}})
		}
		for i, errExpTestData := range vendorConf.Tests.PagerExpressionVariants {
			tests = append(tests, testing.InternalTest{fmt.Sprintf("vendor_%s_pager_%d", vendorConf.Name, i), func(t *testing.T) {
				testutils.ExprTester(t, [][]byte{[]byte(errExpTestData)}, vendorConf.PagerExpression)
			}})
		}

	}
	testing.Main(nil, tests, nil, nil)
	return
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
		if input == nil {
			res = append(res, fmt.Sprintf("cmd=%s nil result\n", commands[i]))
		} else {
			res = append(res, fmt.Sprintf("cmd=%s output=%s status=%d error=%s\n", commands[i], input.Output(), input.Status(), input.Error()))
		}
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

func buildCreds(login, password, host, sshConfigPassphrase string, useSSHConfig bool, logger *zap.Logger) (gcred.Credentials, error) {
	if len(login) == 0 {
		newLogin := gcred.GetLogin()
		login = newLogin
	}

	if useSSHConfig {
		return server.BuildCredsFromSSHConfig(login, password, host, sshConfigPassphrase, "", logger)
	}
	return buildBasicCreds(login, password, logger), nil
}

func buildBasicCreds(login, password string, logger *zap.Logger) gcred.Credentials {
	opts := []gcred.CredentialsOption{
		gcred.WithUsername(login),
		gcred.WithSSHAgentSocket(gcred.GetDefaultAgentSocket()),
		gcred.WithLogger(logger),
	}
	if len(password) > 0 {
		opts = append(opts, gcred.WithPassword(gcred.Secret(password)))
	}
	return gcred.NewSimpleCredentials(opts...)
}

func exec(ctx context.Context, dev device.Device, commands []string, cmdopts []cmd.CmdOption, logger *zap.Logger) ([]cmd.CmdRes, error) {
	err := dev.Connect(ctx)
	if err != nil {
		return nil, err
	}
	var res []cmd.CmdRes
	for _, cmdIter := range commands {
		cRes, err := dev.Execute(cmd.NewCmd(cmdIter, cmdopts...))
		if err != nil {
			logger.Error("error", zap.Any("cmd", cmdIter), zap.Error(err))
			return nil, fmt.Errorf("error executing command %s: %w", cmdIter, err)
		}
		res = append(res, cRes)
	}
	return res, nil
}
