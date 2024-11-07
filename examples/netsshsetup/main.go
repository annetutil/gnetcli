package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

var (
	hostname string
	ipdomain string
	login    string
	password string
	vendor   string
	breed    string
	address  string
	protocol string
	device   NetworkDevice

	rootCmd = &cobra.Command{
		Use:   "netsshsetup",
		Short: "Enable SSH on the network device",

		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			dev := NewDeivce(
				hostname,
				ipdomain,
				login,
				password,
				address,
				vendor,
				breed,
				protocol,
			)
			switch vendor {
			case "cisco":
				device = &CiscoDevice{
					Device: dev,
				}
			}
		},

		RunE: func(cmd *cobra.Command, args []string) error {
			err := device.Ping()
			if err != nil {
				return fmt.Errorf("device is not available")
			}
			sshCheck, err := device.SSHEnabled()
			if !sshCheck {
				err = device.SetSSH()
			}
			return err
		},
	}
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&hostname, "hostname", "", "", "set up hostname")
	rootCmd.PersistentFlags().StringVarP(&ipdomain, "ipdomain", "", "", "set up ipdomain")
	rootCmd.PersistentFlags().StringVarP(&login, "login", "l", "", "set up login")
	rootCmd.PersistentFlags().StringVarP(&password, "password", "p", "", "set up password")
	rootCmd.PersistentFlags().StringVarP(&vendor, "vendor", "v", "", "set up vendor from list: cisco")
	rootCmd.PersistentFlags().StringVarP(&breed, "breed", "b", "", "set up breed from list: ios")
	rootCmd.PersistentFlags().StringVarP(&address, "address", "a", "", "set up ip address")
	rootCmd.PersistentFlags().StringVarP(&protocol, "protocol", "P", "", "set up ip protocol from list: ssh, telnet")
}

func main() {
	Execute()
}
