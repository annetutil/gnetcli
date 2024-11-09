package main

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/annetutil/gnetcli/pkg/cmd"
)

type CiscoDevice struct {
	*Device
}

func (d *CiscoDevice) ShowRun() error {
	_, err := d.Device.SendCommand(cmd.NewCmd("show ip ssh"))
	return err
}

func (d *CiscoDevice) SSHEnabled() (bool, error) {
	data, err := d.Device.SendCommand(cmd.NewCmd("show ip ssh"))
	if err != nil {
		return false, err
	}
	scanner := bufio.NewScanner(bytes.NewReader(data.Output()))
	scanner.Split(bufio.ScanLines)
	var txtlines []string
	for scanner.Scan() {
		txtlines = append(txtlines, scanner.Text())
	}
	for _, line := range txtlines {
		if strings.Contains(line, "SSH Enabled") {
			return true, nil
		}
	}
	return false, nil
}

func (d *CiscoDevice) SetSSH() (error) {
	fmt.Println("Check is ssh enabled")
	cmds := cmd.NewCmdList(
		[]string{
			"conf t",
			fmt.Sprintf("ip domain-name %s", d.Domain),
		},
	)
	cmds = append(cmds, cmd.NewCmd("crypto key generate rsa", cmd.WithAnswers(
		cmd.NewAnswer("How many bits in the modulus [512]:", "2048"),
	), cmd.WithReadTimeout(time.Duration(240*time.Second)), cmd.WithCmdTimeout(time.Duration(600*time.Second))))
	_, err := d.Device.SendCommands(cmds...)
	if err != nil {
		return err
	}
	return nil
}
