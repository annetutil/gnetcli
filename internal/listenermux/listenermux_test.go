package listenermux_test

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/annetutil/gnetcli/internal/listenermux"
	"github.com/stretchr/testify/require"
)

func startMux(t *testing.T) *listenermux.Mux {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	mux, err := listenermux.New(listener)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- mux.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, mux.Close())
		select {
		case err := <-done:
			require.True(t, errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed), "%v", err)
		case <-time.After(2 * time.Second):
			t.Fatal("mux did not stop")
		}
	})
	return mux
}

func TestRoutingAndReplay(t *testing.T) {
	for _, tc := range []struct {
		name, payload string
		grpc          bool
	}{
		{"get", "GET / HTTP/1.1\r\n\r\n", false},
		{"post", "POST /api HTTP/1.1\r\n\r\nbody", false},
		{"partial_preface_mismatch", "PRI / HTTP/1.0\r\n\r\n", false},
		{"http2", "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nframes", true},
		{"tls", "\x16\x03\x03\x00\x05hello", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux := startMux(t)
			client, err := net.Dial("tcp", mux.HTTPListener().Addr().String())
			require.NoError(t, err)
			defer client.Close()
			require.NoError(t, client.SetDeadline(time.Now().Add(3*time.Second)))
			written := make(chan error, 1)
			go func() {
				for _, b := range []byte(tc.payload) {
					if _, err := client.Write([]byte{b}); err != nil {
						written <- err
						return
					}
				}
				written <- nil
			}()
			target := mux.HTTPListener()
			if tc.grpc {
				target = mux.GRPCListener()
			}
			accepted := make(chan net.Conn, 1)
			go func() { c, _ := target.Accept(); accepted <- c }()
			select {
			case conn := <-accepted:
				require.NotNil(t, conn)
				defer conn.Close()
				require.NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
				data := make([]byte, len(tc.payload))
				_, err = io.ReadFull(conn, data)
				require.NoError(t, err)
				require.Equal(t, tc.payload, string(data))
			case <-time.After(3 * time.Second):
				t.Fatal("wrong route")
			}
			require.NoError(t, <-written)
		})
	}
}

func TestCloseDoesNotOwnHandedOffConnections(t *testing.T) {
	// Close immediately after Accept returns; the classifier goroutine may not
	// yet have resumed after its unbuffered channel send.
	for i := 0; i < 100; i++ {
		mux := startMux(t)
		client, err := net.Dial("tcp", mux.HTTPListener().Addr().String())
		require.NoError(t, err)
		_, err = client.Write([]byte("G"))
		require.NoError(t, err)
		conn, err := mux.HTTPListener().Accept()
		require.NoError(t, err)
		require.NoError(t, mux.Close())
		require.NoError(t, conn.SetDeadline(time.Now().Add(time.Second)))
		_, err = client.Write([]byte("still open"))
		require.NoError(t, err)
		data := make([]byte, len("Gstill open"))
		_, err = io.ReadFull(conn, data)
		require.NoError(t, err)
		require.Equal(t, "Gstill open", string(data))
		conn.Close()
		client.Close()
	}
}

func TestCloseUnblocksPendingConnectionsAndAccept(t *testing.T) {
	mux := startMux(t)
	client, err := net.Dial("tcp", mux.HTTPListener().Addr().String())
	require.NoError(t, err)
	defer client.Close()
	_, err = client.Write([]byte("PRI")) // An incomplete HTTP/2 preface.
	require.NoError(t, err)
	require.NoError(t, mux.Close())
	require.NoError(t, mux.Close())
	require.NoError(t, client.SetReadDeadline(time.Now().Add(time.Second)))
	_, err = client.Read(make([]byte, 1))
	require.Error(t, err)
	if nerr, ok := err.(net.Error); ok {
		require.False(t, nerr.Timeout())
	}
	_, err = mux.HTTPListener().Accept()
	require.ErrorIs(t, err, net.ErrClosed)
	_, err = mux.GRPCListener().Accept()
	require.ErrorIs(t, err, net.ErrClosed)
}

func TestSilentConnectionTimesOut(t *testing.T) {
	mux := startMux(t)
	client, err := net.Dial("tcp", mux.HTTPListener().Addr().String())
	require.NoError(t, err)
	defer client.Close()
	require.NoError(t, client.SetReadDeadline(time.Now().Add(7*time.Second)))
	_, err = client.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)
}
