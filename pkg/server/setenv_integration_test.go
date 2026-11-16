package server_test

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"testing"
	"time"

	pb "github.com/annetutil/gnetcli/pkg/server/proto"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

func TestSSHConfigSetEnv(t *testing.T) {
	for _, tc := range []struct {
		name, directive string
		env             map[string]string
		reject          bool
	}{
		{"original_host", `SetEnv SWITCH=%n NOTE="two words" EMPTY= PERCENT=%%`, map[string]string{"SWITCH": "switch.example.net", "NOTE": "two words", "EMPTY": "", "PERCENT": "%"}, false},
		{"ordinary_shell", "", nil, false},
		{"refused_env", "SetEnv SWITCH=%n", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, port := newSSHServerPort(t)
			_, key, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			signer, err := ssh.NewSignerFromKey(key)
			require.NoError(t, err)
			config := &ssh.ServerConfig{NoClientAuth: true}
			config.AddHostKey(signer)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				sshConn, channels, requests, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				defer sshConn.Close()
				go ssh.DiscardRequests(requests)
				for incoming := range channels {
					if incoming.ChannelType() != "session" {
						_ = incoming.Reject(ssh.UnknownChannelType, "session required")
						continue
					}
					channel, reqs, err := incoming.Accept()
					if err != nil {
						return
					}
					defer channel.Close()
					pty := false
					received := map[string]string{}
					for req := range reqs {
						switch req.Type {
						case "env":
							var value struct{ Name, Value string }
							ok := !tc.reject && !pty && ssh.Unmarshal(req.Payload, &value) == nil
							if ok {
								received[value.Name] = value.Value
							}
							_ = req.Reply(ok, nil)
						case "pty-req":
							pty = true
							_ = req.Reply(true, nil)
						case "shell":
							ok := pty && len(received) == len(tc.env)
							for name, value := range tc.env {
								actual, exists := received[name]
								ok = ok && exists && value == actual
							}
							_ = req.Reply(ok, nil)
							if !ok {
								continue
							}
							_, _ = io.WriteString(channel, "switch#")
							scanner := bufio.NewScanner(channel)
							for scanner.Scan() {
								command := scanner.Text()
								_, _ = fmt.Fprintf(channel, "%s\r\nresult: %s\r\nswitch#", command, command)
							}
							return
						default:
							_ = req.Reply(false, nil)
						}
					}
				}
			}()
			cfg := serverConfigFromYAML(t, "dev_auth:\n  ssh_config: true\n")
			sshConfig := fmt.Sprintf("Host switch.example.net\n HostName 127.0.0.1\n Port %d\n User tester\n %s\n", port, tc.directive)
			client := newGnetcliTestClient(t, cfg, sshConfig, zap.NewNop())
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			chat, err := client.ExecChat(ctx)
			require.NoError(t, err)
			defer chat.CloseSend()
			for _, command := range []string{"show version", "show interfaces"} {
				require.NoError(t, chat.Send(&pb.CMD{Host: "switch.example.net", Cmd: command, HostParams: &pb.HostParams{Device: "cisco", Ip: "192.0.2.1"}}))
				result, err := chat.Recv()
				if tc.reject {
					require.ErrorContains(t, err, "unable to set env")
					return
				}
				require.NoError(t, err)
				require.Zero(t, result.GetStatus())
				require.Contains(t, string(result.GetOut()), "result: "+command)
			}
		})
	}
}
