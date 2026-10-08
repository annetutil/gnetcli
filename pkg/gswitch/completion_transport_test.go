package gswitch_test

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestSSHInteractiveTabCompletion(t *testing.T) {
	d := newEmulatedSwitch(t, "iosxe.yaml")
	address, _ := startSwitch(t, emulatedOptions(d), false)
	conn, err := net.DialTimeout("tcp", address, time.Second)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	config := &ssh.ClientConfig{User: "test", Auth: []ssh.AuthMethod{ssh.Password("secret")}, HostKeyCallback: ssh.InsecureIgnoreHostKey()}
	c, chans, requests, err := ssh.NewClientConn(conn, address, config)
	require.NoError(t, err)
	client := ssh.NewClient(c, chans, requests)
	defer client.Close()
	session, err := client.NewSession()
	require.NoError(t, err)
	defer session.Close()
	stdin, err := session.StdinPipe()
	require.NoError(t, err)
	stdout, err := session.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, session.RequestPty("vt100", 24, 80, nil))
	require.NoError(t, session.Shell())
	reader := bufio.NewReader(stdout)
	read := func(suffix string) string {
		var out strings.Builder
		for !strings.HasSuffix(out.String(), suffix) {
			b, err := reader.ReadByte()
			require.NoError(t, err)
			out.WriteByte(b)
		}
		return out.String()
	}
	send := func(text string) { _, err := io.WriteString(stdin, text); require.NoError(t, err) }
	read("sw1>")
	send("en\t")
	require.Equal(t, "enable ", read("enable "))
	require.Equal(t, "user", d.Snapshot().Sessions[0].Mode)
	send("\n")
	read("sw1#")
	send("sh\t")
	require.Equal(t, "show ", read("show "))
	send("\t")
	choices := read("sw1#show ")
	require.Contains(t, choices, "running-config\r\nslow\r\nversion")
	send("v\t")
	require.Equal(t, "version ", read("version "))
	send("\n")
	require.Contains(t, read("sw1#"), "Cisco IOS XE Software")
	send("conf\tt\t")
	read("configure terminal ")
	require.Equal(t, "exec", d.Snapshot().Sessions[0].Mode)
	send("\n")
	read("sw1(config)#")
	send("int\tEthernet1\n")
	read("sw1(config-if)#")
	send("des\tvia-tab\n")
	read("sw1(config-if)#")
	require.Equal(t, "via-tab", d.Snapshot().Running["interfaces"].(map[string]any)["Ethernet1"].(map[string]any)["description"])
}
