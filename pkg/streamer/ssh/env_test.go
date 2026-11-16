package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
)

func TestRejectedEnvReturnsErrorAndClosesSession(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := gossh.NewSignerFromKey(key)
	require.NoError(t, err)
	config := &gossh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	stop := make(chan struct{})
	serverDone := make(chan struct{})
	sessionClosed := make(chan error, 1)
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		sshConn, channels, requests, err := gossh.NewServerConn(conn, config)
		if err != nil {
			sessionClosed <- err
			return
		}
		defer sshConn.Close()
		go gossh.DiscardRequests(requests)
		incoming, ok := <-channels
		if !ok {
			sessionClosed <- fmt.Errorf("no session channel")
			return
		}
		channel, reqs, err := incoming.Accept()
		if err != nil {
			sessionClosed <- err
			return
		}
		defer channel.Close()
		receivedEnv := false
		for request := range reqs {
			var env struct{ Name, Value string }
			if request.Type != "env" || gossh.Unmarshal(request.Payload, &env) != nil || env.Name != "TEST_ENV" || env.Value != "test-value" {
				sessionClosed <- fmt.Errorf("unexpected SSH request %q", request.Type)
				return
			}
			receivedEnv = true
			if err := request.Reply(false, nil); err != nil {
				sessionClosed <- err
				return
			}
			// Keep the channel open without stdout/stderr or EOF after rejection.
		}
		if !receivedEnv {
			sessionClosed <- fmt.Errorf("no env request")
			return
		}
		sessionClosed <- nil
		// The client must close the failed channel, not depend on a connection EOF.
		<-stop
	}()
	client := NewStreamer("127.0.0.1", credentials.NewSimpleCredentials(credentials.WithUsername("tester")), WithPort(listener.Addr().(*net.TCPAddr).Port), WithEnv("TEST_ENV", "test-value"))
	writeDone := make(chan struct{})
	writeStarted := false
	t.Cleanup(func() {
		client.Close()
		close(stop)
		_ = listener.Close()
		if writeStarted {
			select {
			case <-writeDone:
			case <-time.After(time.Second):
				t.Error("Write did not stop after connection close")
			}
		}
		select {
		case <-serverDone:
		case <-time.After(time.Second):
			t.Error("SSH test server did not stop")
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, client.Init(ctx))
	result := make(chan error, 1)
	writeStarted = true
	go func() { defer close(writeDone); result <- client.Write([]byte("show version\n")) }()
	select {
	case err := <-result:
		require.ErrorContains(t, err, "unable to set env TEST_ENV")
		require.ErrorContains(t, err, "ssh: setenv failed")
	case <-time.After(2 * time.Second):
		t.Fatal("Write blocked after the server rejected env without sending output")
	}
	select {
	case err := <-sessionClosed:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("failed SSH session channel was not closed")
	}
}
