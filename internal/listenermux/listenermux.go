// Package listenermux shares a TCP listener between plaintext HTTP/1 and native
// gRPC. HTTP/2 connections and TLS handshakes are passed unchanged to gRPC.
package listenermux

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
const sniffTimeout = 5 * time.Second

// Mux owns a listener and any connections not yet handed to a protocol server.
// Close leaves handed-off connections open for those servers to drain.
// This is connection-level routing: HTTP/2 REST and HTTPS are not supported.
type Mux struct {
	listener   net.Listener
	http, grpc *subListener
	done       chan struct{}
	once       sync.Once
	closeErr   error
	mu         sync.Mutex
	pending    map[net.Conn]struct{}
	workers    sync.WaitGroup
}

func New(listener net.Listener) (*Mux, error) {
	if listener == nil {
		return nil, errors.New("nil listener")
	}
	m := &Mux{listener: listener, done: make(chan struct{}), pending: make(map[net.Conn]struct{})}
	m.http = &subListener{parent: m, conns: make(chan net.Conn), done: make(chan struct{})}
	m.grpc = &subListener{parent: m, conns: make(chan net.Conn), done: make(chan struct{})}
	return m, nil
}

func (m *Mux) HTTPListener() net.Listener { return m.http }
func (m *Mux) GRPCListener() net.Listener { return m.grpc }

// Serve must be called exactly once. It waits for classifiers on exit.
func (m *Mux) Serve(ctx context.Context) error {
	stop := context.AfterFunc(ctx, func() { _ = m.Close() })
	defer stop()
	defer func() { _ = m.Close(); m.workers.Wait() }()
	for {
		conn, err := m.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		m.mu.Lock()
		select {
		case <-m.done:
			m.mu.Unlock()
			_ = conn.Close()
			continue
		default:
			m.pending[conn] = struct{}{}
		}
		m.mu.Unlock()
		m.workers.Add(1)
		go m.route(conn)
	}
}

func (m *Mux) Close() error {
	m.once.Do(func() {
		close(m.done)
		m.closeErr = m.listener.Close()
		m.mu.Lock()
		defer m.mu.Unlock()
		for conn := range m.pending {
			_ = conn.Close()
		}
	})
	return m.closeErr
}

func (m *Mux) route(conn net.Conn) {
	defer m.workers.Done()
	isGRPC, wrapped, err := sniff(conn)
	// Relinquish ownership BEFORE handoff: otherwise Close could close a
	// connection already being served while the sender is still resuming.
	m.mu.Lock()
	delete(m.pending, conn)
	m.mu.Unlock()
	if err != nil {
		_ = conn.Close()
		return
	}
	target := m.http
	if isGRPC {
		target = m.grpc
	}
	select {
	case target.conns <- wrapped:
	case <-target.done:
		_ = conn.Close()
	case <-m.done:
		_ = conn.Close()
	}
}

func sniff(conn net.Conn) (bool, net.Conn, error) {
	if err := conn.SetReadDeadline(time.Now().Add(sniffTimeout)); err != nil {
		return false, nil, err
	}
	prefix := make([]byte, 0, len(preface))
	readByte := func() (byte, error) {
		var b [1]byte
		_, err := io.ReadFull(conn, b[:])
		if err == nil {
			prefix = append(prefix, b[0])
		}
		return b[0], err
	}
	first, err := readByte()
	if err != nil {
		return false, nil, err
	}
	grpc := false
	if first == 22 { // TLS handshake record, with its major/minor version.
		major, err := readByte()
		if err != nil {
			return false, nil, err
		}
		if _, err = readByte(); err != nil {
			return false, nil, err
		}
		grpc = major == 3
	} else if first == preface[0] {
		grpc = true
		for i := 1; i < len(preface); i++ {
			b, err := readByte()
			if err != nil {
				return false, nil, err
			}
			if b != preface[i] {
				grpc = false
				break
			}
		}
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return false, nil, err
	}
	return grpc, &replayConn{Conn: conn, reader: io.MultiReader(bytes.NewReader(prefix), conn)}, nil
}

type replayConn struct {
	net.Conn
	reader io.Reader
}

func (c *replayConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

type subListener struct {
	parent *Mux
	conns  chan net.Conn
	done   chan struct{}
	once   sync.Once
}

func (l *subListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	case <-l.parent.done:
		return nil, net.ErrClosed
	}
}
func (l *subListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *subListener) Addr() net.Addr { return l.parent.listener.Addr() }
