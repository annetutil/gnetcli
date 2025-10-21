package main

import "strings"

type vendor struct {
	promptMaker         func(state *CLIState) string
	loginPromptMaker    func(state *CLIState) string
	passwordPromptMaker func(state *CLIState) string
	handleCommand       func(state *CLIState, command string) (commandResult, string, error)
	handleConfigCommand func(state *CLIState, command string) (commandResult, string, error)
}

var vendors = map[string]vendor{}

func init() {
	ciscoVendorCommands := map[string]string{
		"show version":                       showVersion(),
		"terminal length 0":                  "Terminal length set to 0.",
		"copy running-config startup-config": "",
	}
	vendors["cisco"] = vendor{
		promptMaker: func(state *CLIState) string {
			if state.mode == ModeConfig {
				return state.hostname + "(config)#"
			}
			return state.hostname + "#"
		},
		loginPromptMaker: func(state *CLIState) string {
			return "Username: "
		},
		passwordPromptMaker: func(state *CLIState) string {
			return "Password: "
		},
		handleCommand: func(state *CLIState, command string) (commandResult, string, error) {
			if v, ok := ciscoVendorCommands[command]; ok {
				return commandResultContinue, v, nil
			}
			switch command {
			case "enable":
				state.NewMode(ModeEnable)
				return commandResultContinue, "", nil
			case "q", "exit", "logout":
				return commandResultExit, "", nil
			case "conf t":
				state.NewMode(ModeConfig)
				return commandResultContinue, "", nil
			case "?":
				res := strings.Builder{}
				res.WriteString("\r\n")
				for k := range ciscoVendorCommands {
					res.WriteString("    ")
					res.WriteString(k)
					res.WriteString(" - ")
					res.WriteString(k)
					res.WriteString("\r\n")
				}
				return commandResultContinue, res.String(), nil
			case "show running-config":
				res := strings.Builder{}
				res.WriteString("\r\n")
				for k := range state.config {
					res.WriteString(k)
					res.WriteString("\r\n")
				}
				return commandResultContinue, res.String(), nil
			case "":
				return commandResultContinue, "", nil
			}
			return commandResultContinue, "% Invalid command at '^' marker.", nil
		},
		handleConfigCommand: func(state *CLIState, command string) (commandResult, string, error) {
			switch command {
			case "q", "exit", "logout":
				if state.mode == ModeConfig {
					state.NewMode(ModeUser)
				}
				return commandResultContinue, "", nil
			}
			state.config[command] = true
			return commandResultContinue, "", nil
		},
	}
}

func showVersion() string {
	return "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11\r\n" +
		"Technical Support: http://www.cisco.com/techsupport\r\n" +
		"Copyright (c) 1986-2016 by Cisco Systems, Inc.\r\n"
}
