package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/scrapli/scrapligo/driver/network"
	"github.com/scrapli/scrapligo/driver/options"
	"github.com/scrapli/scrapligo/logging"
	"github.com/scrapli/scrapligo/platform"
	"github.com/scrapli/scrapligo/response"
)

const gvendorConf = `
---
platform-type: 'gvendor_os'
default:
  driver-type: 'network'

  privilege-levels:
    exec:
      name: 'exec'
      pattern: '(?im)^(?P<user>[\w]{1,63})@(?P<host>[\w]{1,63})> $'
      previous-priv:
      deescalate:
      escalate:
      escalate-auth: false
      escalate-prompt:
  default-desired-privilege-level: 'exec'

  failed-when-contains:
    - '% Ambiguous command'
    - '% Incomplete command'
    - '% Invalid input detected'
    - '% Unknown command'
`

func main() {
	debug := flag.Bool("debug", false, "Set debug log level")
	host := flag.String("host", "localhost", "Server host")
	report := flag.String("report", "", "Path to report")
	port := flag.Int("port", 2222, "Server port")
	flag.Parse()
	level := logging.Critical
	if *debug {
		level = logging.Debug
	}
	logger, err := logging.NewInstance(
		logging.WithLevel(level),
		logging.WithLogger(log.Print),
	)
	if err != nil {
		panic(err)
	}
	res := NewResult()
	conn, err := connect(*host, *port, logger)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	start := time.Now()
	var lastErr error
	for {
		nextCmdRes, err := conn.SendCommand(NextCmd)
		addResult(res, NextCmd, nextCmdRes, err)
		if err != nil {
			lastErr = err
			break
		}
		parsedResult := dropPrompt(nextCmdRes.RawResult)
		cmdRes, err := conn.SendCommand(string(parsedResult))
		addResult(res, string(parsedResult), cmdRes, err)
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

func dropPrompt(data []byte) []byte {
	r := bytes.LastIndex(data, []byte("\n"))
	if r > 0 {
		return data[0:r]
	}
	return data
}

func addResult(res *Result, cmd string, cmdRes *response.Response, err error) {
	cmdResP := []byte{}
	if cmdRes != nil {
		cmdResP = dropPrompt(cmdRes.RawResult)
	}
	res.Add(cmd, cmdResP, err)
}

func connect(host string, port int, logger *logging.Instance) (*network.Driver, error) {
	platformIns, err := platform.NewPlatform(
		[]byte(gvendorConf),
		host,
		options.WithAuthNoStrictKey(),
		options.WithPort(port),
		options.WithLogger(logger),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create platform; error: %w", err)
	}

	d, err := platformIns.GetNetworkDriver()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch network driver from the platform; error: %w", err)
	}

	err = d.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open driver; error: %w", err)
	}

	return d, nil
}
