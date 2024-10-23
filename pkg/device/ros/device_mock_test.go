package ros

import (
	"testing"

	"github.com/annetutil/gnetcli/pkg/device"
	"github.com/annetutil/gnetcli/pkg/streamer"
	m "github.com/annetutil/gnetcli/pkg/testutils/mock"
)

var (
	helloMsg = []m.Action{
		m.Send("\r\r\n\r\r\n\r\r\n\r\r\n\r\r\n\r\r\n\r\r\n\r\n\r  MMM      MMM       KKK                          " +
			"TTTTTTTTTTT      KKK\r\n\r  MMMM    MMMM       KKK                          TTTTTTTTTTT      KKK\r\n\r  MM" +
			"M MMMM MMM  III  KKK  KKK  RRRRRR     OOOOOO      TTT     III  KKK  KKK\r\n\r  MMM  MM  MMM  III  KKKKK   " +
			"  RRR  RRR  OOO  OOO     TTT     III  KKKKK\r\n\r  MMM      MMM  III  KKK KKK   RRRRRR    OOO  OOO     TTT" +
			"     III  KKK KKK\r\n\r  MMM      MMM  III  KKK  KKK  RRR  RRR   OOOOOO      TTT     III  KKK  KKK\r\n\r\r" +
			"\n\r  MikroTik RouterOS 6.49.17 (c) 1999-2024       http://www.mikrotik.com/\r\n\r\r\n[?]             Give" +
			"s the list of available commands\r\n\rcommand [?]     Gives help on the command and list of arguments\r\n" +
			"\r\r\n\r[Tab]           Completes the command/word. If the input is ambiguous,\r\n\r                a seco" +
			"nd [Tab] gives possible options\r\n\r\r\n\r/               Move up to base level\r\n"),
		m.Send("\r..              Move up one level\r\n\r/command        Use command at the base level\r\n\r\r\r\r" +
			"\r\r[username12345@mk-rb3011-test] >                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      \r[username12345@mk-rb3011-test] > "),
	}

	byeMsg = []m.Action{
		m.Close(),
	}
)

func TestRos(t *testing.T) {
	testCases := []struct {
		name    string
		command string
		result  string
		dialog  [][]m.Action
	}{
		{
			name:    "ip service export",
			command: "/ip service export",
			result: "" +
				"# oct/17/2024 10:17:11 by RouterOS 6.49.17\n" +
				"# software id = 1111-1111\n" +
				"#\n" +
				"# model = RB3011UiAS\n" +
				"# serial number = 111111111111\n" +
				"/ip service\n" +
				"set telnet disabled=yes\n" +
				"set ftp disabled=yes\n" +
				"set www disabled=yes\n" +
				"set api disabled=yes\n" +
				"set api-ssl disabled=yes" +
				"\n",
			dialog: [][]m.Action{
				helloMsg,
				{
					m.Expect("/ip service export"),
					m.Expect("\r\n"),
					m.Send("" +
						"/\r\r[username12345@mk-rb3011-test] > /                                                       " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                               \u001b[K\r[username12345@mk-rb3" +
						"011-test] > /i\r\r[username12345@mk-rb3011-test] > /i                                         " +
						"                                                                                              " +
						"                                                                    " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"        \u001b[K\r[username12345@mk-rb3011-test] > /ip\r\r[username12345@mk-rb3011-test] > /ip" +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                      \u001b[K\r[username12345@mk-rb3011-test] > /ip \r\r[username12345@mk-rb3" +
						"011-test] > /ip                                                                               " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                     \u001b[K\r[username12345@mk-rb3011-test] > /ip s\r\r[user" +
						"name12345@mk-rb3011-test] > /ip s                                                             " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                     \u001b[K\r[username12345@mk-rb3011-test] " +
						"> /ip se\r\r[username12345@mk-rb3011-test] > /ip se                                           " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                      \u001b[K\r[username12345" +
						"@mk-rb3011-test] > /ip ser\r\r[username12345@mk-rb3011-test] > /ip ser                        " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                        \u001b" +
						"[K\r[username12345@mk-rb3011-test] > /ip serv\r\r[username12345@mk-rb3011-test] > /ip serv    " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"             \u001b[K\r[username12345@mk-rb3011-test] > /ip servi\r\r[username12345@mk-rb3011-" +
						"test] > /ip servi                                                                             " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                 \u001b[K\r[username12345@mk-rb3011-test] > /ip servic\r\r[use" +
						"rname12345@mk-rb3011-test] > /ip servic                                                       " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                      \u001b[K\r[username12345@mk-rb3011-test]" +
						" > /ip service\r\r[username12345@mk-rb3011-test] > /ip service                                " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                            \u001b[K\r[usernam" +
						"e12345@mk-rb3011-test] > /ip service \r\r[username12345@mk-rb3011-test] > /ip service         " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"     \u001b[K\r[username12345@mk-rb3011-test] > /ip service e\r\r[username12345@mk-rb3011-test" +
						"] > /ip service e                                                                             " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                             \u001b[K\r[username12345@mk-rb3011-test] > /ip service ex\r\r[use" +
						"rname12345@mk-rb3011-test] > /ip service ex                                                   " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                      \u001b[K\r[username12345@mk-rb3011-test]" +
						" > /ip service exp\r\r[username12345@mk-rb3011-test] > /ip service exp                        " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                \u001b[K\r[use" +
						"rname12345@mk-rb3011-test] > /ip service expo\r\r[username12345@mk-rb3011-test] > /ip service " +
						"expo                                                                                          " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"             \u001b[K\r[username12345@mk-rb3011-test] > /ip service expor\r\r[username12345@mk" +
						"-rb3011-test] > /ip service expor                                                             " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                         \u001b[K\r[username12345@mk-rb3011-test] > /ip servic" +
						"e export\r\r[username12345@mk-rb3011-test] > /ip service export                               " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                      \u001b[K\r[username12345" +
						"@mk-rb3011-test] > /ip service export\r[username12345@mk-rb3011-test] > /ip service export\r\n" +
						"\r# oct/17/2024 10:17:11 by RouterOS 6.49.17\r\n# software id = 1111-1111\r\n#\r\n# model = RB" +
						"3011UiAS\r\n# serial number = 111111111111\r\n/ip service\r\nset telnet disabled=yes\r\nset ft" +
						"p disabled=yes\r\nset www disabled=yes\r\nset api disabled=yes\r\nset api-ssl disabled=yes\r\n" +
						"\r\r\r\r[username12345@mk-rb3011-test] >                                                      " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                  \r[username12345@mk-rb3011-t" +
						"est] > \r\r[username12345@mk-rb3011-test3] >                                                   " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                                              " +
						"                                                                     \u001b[K\r" +
						"",
					),
					m.Send("[username12345@mk-rb3011-test2] > "),
				},
				byeMsg,
			},
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.name, func(t *testing.T) {
			actions := m.ConcatMultipleSlices(tc.dialog)
			m.RunDialogWithDefaultCreds(t, func(connector streamer.Connector) device.Device {
				dev := NewDevice(connector)
				return &dev
			}, actions, tc.command, tc.result)
		})
	}
}
