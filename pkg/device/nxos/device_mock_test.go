package nxos

import (
	"testing"

	"github.com/annetutil/gnetcli/pkg/device"
	"github.com/annetutil/gnetcli/pkg/streamer"
	m "github.com/annetutil/gnetcli/pkg/testutils/mock"
)

var prompt = "n9k-test# "
var motd = "\r\n" +
	"Cisco Nexus Operating System (NX-OS) Software\r\nTAC support: " +
	"http://www.cisco.com/tac\r\nCopyright (C) 2002-2021, Cisco and" +
	"/or its affiliates.\r\nAll rights reserved.\r\nThe copyrights to" +
	" certain works contained in this software are\r\nowned by othe" +
	"r third parties and used and distributed under their own\r\nli" +
	"censes, such as open source.  This software is provided \"as " +
	"is,\" and unless\r\notherwise stated, there is no warranty, exp" +
	"ress or implied, including but not\r\nlimited to warranties of" +
	" merchantability and fitness for a particular purpose.\r\nCert" +
	"ain components of this software are licensed under\r\nthe GNU " +
	"General Public License (GPL) version 2.0 or \r\nGNU General Pu" +
	"blic License (GPL) version 3.0  or the GNU\r\nLesser General P" +
	"ublic License (LGPL) Version 2.1 or \r\nLesser General Public " +
	"License (LGPL) Version 2.0. \r\nA copy of each such license is" +
	" available at\r\nhttp://www.opensource.org/licenses/gpl-2.0.ph" +
	"p and\r\nhttp://opensource.org/licenses/gpl-3.0.html and\r\nhttp" +
	"://www.opensource.org/licenses/lgpl-2.1.php and\r\nhttp://www." +
	"gnu.org/licenses/old-licenses/library.txt.\r\n\r"

var defaultDialog = []m.Action{
	m.Send(motd),
	m.Send(prompt),

	m.Expect("terminal length 0\n"),
	m.SendEcho("terminal length 0\r\r\n"),
	m.Send(prompt),
}

func TestValidCommands(t *testing.T) {
	testCases := []struct {
		name    string
		command string
		result  string
		dialog  []m.Action
	}{
		{
			name:    "Test show hostname",
			command: "show hostname",
			result:  "n9k-test ", // trailing space is expected
			dialog: append(
				defaultDialog,
				[]m.Action{
					m.Expect("show hostname\n"),
					m.SendEcho("show hostname\r\r\n"),
					m.Send("n9k-test \r\n\r"),
					m.Send(prompt),
					m.Close(),
				}...,
			),
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.name, func(t *testing.T) {
			m.RunDialogWithDefaultCreds(t, func(connector streamer.Connector) device.Device {
				dev := NewDevice(connector)
				return &dev
			}, tc.dialog, tc.command, tc.result)
		})
	}
}
