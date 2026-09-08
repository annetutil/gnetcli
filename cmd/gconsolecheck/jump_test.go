package main

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSplitJumpTarget(t *testing.T) {
	testCases := []struct {
		value    string
		username string
		host     string
	}{
		{value: "jump.example.net", host: "jump.example.net"},
		{value: "user@jump.example.net", username: "user", host: "jump.example.net"},
		{value: "2001:db8::1", host: "2001:db8::1"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.value, func(t *testing.T) {
			username, host, err := splitJumpTarget(testCase.value)
			require.NoError(t, err)
			require.Equal(t, testCase.username, username)
			require.Equal(t, testCase.host, host)
		})
	}
}

type fakeTunnel struct {
	connectCalls atomic.Int64
	closeCalls   atomic.Int64
	connected    atomic.Bool
}

func (t *fakeTunnel) CreateConnect(context.Context) error {
	t.connectCalls.Add(1)
	time.Sleep(10 * time.Millisecond)
	t.connected.Store(true)
	return nil
}

func (t *fakeTunnel) StartForward(string) (net.Conn, error) { return nil, nil }
func (t *fakeTunnel) IsConnected() bool                     { return t.connected.Load() }
func (t *fakeTunnel) Close() {
	t.closeCalls.Add(1)
	t.connected.Store(false)
}

func TestManagedTunnelConnectsOnce(t *testing.T) {
	underlying := &fakeTunnel{}
	tunnel := &managedTunnel{tunnel: underlying}
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			require.NoError(t, tunnel.EnsureConnected(context.Background(), time.Second))
		}()
	}
	wg.Wait()

	require.Equal(t, int64(1), underlying.connectCalls.Load())
	tunnel.Close()
	require.Equal(t, int64(1), underlying.closeCalls.Load())
}
