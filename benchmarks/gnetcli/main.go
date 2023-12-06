package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"regexp"
	"time"

	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/device"
	"github.com/annetutil/gnetcli/pkg/device/genericcli"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/streamer"
	"github.com/annetutil/gnetcli/pkg/streamer/ssh"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

const conf = `
devices:
  - name: gvendor_os
    prompt_expression: '(?im)^(?P<user>[\w]{1,63})@(?P<host>[\w]{1,63})> $'
    error_expression: '\^\r\nError:'
`

func main() {
	debug := flag.Bool("debug", false, "Set debug log level")
	host := flag.String("host", "localhost", "Server host")
	report := flag.String("report", "", "Path to report")
	port := flag.Int("port", 2222, "Server port")
	flag.Parse()
	logConfig := zap.NewProductionConfig()
	if *debug {
		logConfig = zap.NewDevelopmentConfig()
	}
	logger := zap.Must(logConfig.Build())

	creds := credentials.NewSimpleCredentials(
		credentials.WithLogger(logger),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	devicesStor, err := LoadYamlDeviceConfigs([]byte(conf))
	gvendorOs := devicesStor["gvendor_os"]
	devFn := GenericCLIDevToDev(gvendorOs)
	connector := ssh.NewStreamer(*host, creds, ssh.WithLogger(logger), ssh.WithPort(*port))
	var conn device.Device
	conn = devFn(connector)
	err = conn.Connect(ctx)
	if err != nil {
		panic(err)
	}

	res := NewResult()
	start := time.Now()
	var lastErr error
	for {
		nextCmdRes, err := conn.Execute(cmd.NewCmd(NextCmd))
		addResult(res, NextCmd, nextCmdRes, err)
		if err != nil {
			lastErr = err
			break
		}
		nextCmdResParsed := string(bytes.TrimRight(nextCmdRes.Output(), "\r\n"))
		cmdRes, err := conn.Execute(cmd.NewCmd(nextCmdResParsed))
		addResult(res, nextCmdResParsed, cmdRes, err)
		if err != nil {
			lastErr = err
			break
		}
	}
	duration := time.Since(start)
	res.SetDuration(duration)
	if len(*report) > 0 {
		err = SaveReport(*report, res)
		if err != nil {
			panic(err)
		}
	}
	fmt.Printf("duration=%fs commands=%d lastErr=%s\n", res.Duration.Seconds(), len(res.Items), lastErr.Error())
}

type DevConf struct {
	Name             string `yaml:"name"`
	PromptExpression string `yaml:"prompt_expression"`
	ErrorExpression  string `yaml:"error_expression"`
	PagerExpression  string `yaml:"pager_expression"`
}

type DevConfs []DevConf

func NewConf() *Conf {
	return &Conf{}
}

type Conf struct {
	Devices DevConfs `yaml:"devices"`
}

func (m DevConfs) Make() (map[string]*genericcli.GenericCLI, error) {
	res := map[string]*genericcli.GenericCLI{}
	for _, v := range m {
		dev, err := v.Make()
		if err != nil {
			return nil, fmt.Errorf("dev %v error %w", v, err)
		}
		res[v.Name] = dev
	}

	return res, nil
}

func (m DevConf) Make() (*genericcli.GenericCLI, error) {
	opts := []genericcli.GenericCLIOption{
		genericcli.WithSFTPEnabled(),
	}
	errorExpr := m.ErrorExpression
	if len(errorExpr) > 0 {
		_, err := regexp.Compile(errorExpr)
		if err != nil {
			return nil, fmt.Errorf("error expression error %w", err)
		}
	} else {
		errorExpr = "$.^" // must not match anything
	}

	if len(m.PagerExpression) > 0 {
		_, err := regexp.Compile(m.PagerExpression)
		if err != nil {
			return nil, fmt.Errorf("pager expression error %w", err)
		}
		opts = append(opts, genericcli.WithPager(expr.NewSimpleExprLast200(m.PagerExpression)))
	}

	cli := genericcli.MakeGenericCLI(
		expr.NewSimpleExprLast200(m.PromptExpression),
		expr.NewSimpleExprLast200(errorExpr),
		opts...,
	)
	return &cli, nil
}

func GenericCLIDevToDev(cli *genericcli.GenericCLI, opts ...genericcli.GenericDeviceOption) func(connector streamer.Connector) device.Device {
	return func(connector streamer.Connector) device.Device {
		res := genericcli.MakeGenericDevice(*cli, connector, opts...)
		return &res
	}
}

func LoadYamlDeviceConfigs(content []byte) (map[string]*genericcli.GenericCLI, error) {
	conf := NewConf()
	err := yaml.Unmarshal(content, &conf)
	if err != nil {
		return nil, err
	}
	res, err := conf.Devices.Make()
	if err != nil {
		return nil, err
	}
	return res, nil
}

func addResult(res *Result, cmd string, cmdRes cmd.CmdRes, err error) {
	var cmdResP []byte
	if cmdRes != nil {
		cmdResP = cmdRes.Output()
		cmdResP = bytes.TrimRight(cmdResP, "\r\n")
	}
	fmt.Printf("olo=%v\n", cmdResP)

	res.Add(cmd, cmdResP, err)
}
