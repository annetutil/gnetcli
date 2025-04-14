package tssh

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	_ "unsafe"

	"golang.org/x/crypto/ssh"
)

//go:linkname newMux golang.org/x/crypto/ssh.newMux
func newMux(p packetConn) *mux

//go:linkname muxSendRequest golang.org/x/crypto/ssh.(*mux).SendRequest
func muxSendRequest(m *mux, name string, wantReply bool, payload []byte) (bool, []byte, error)

//go:linkname muxOpenChannel golang.org/x/crypto/ssh.(*mux).OpenChannel
func muxOpenChannel(m *mux, chanType string, extra []byte) (ssh.Channel, <-chan *ssh.Request, error)

//go:linkname muxWait golang.org/x/crypto/ssh.(*mux).Wait
func muxWait(m *mux) error

// packetConn represents a transport that implements packet based
// operations.
type packetConn interface {
	// Encrypt and send a packet of data to the remote peer.
	writePacket(packet []byte) error

	// Read a packet from the connection. The read is blocking,
	// i.e. if error is nil, then the returned byte slice is
	// always non-empty.
	readPacket() ([]byte, error)

	// Close closes the write-side of the connection.
	Close() error
}

// channel is an implementation of the Channel interface that works
// with the mux class.
type channel struct{} //lint:ignore U1000 for linkname

// chanList is a thread safe channel list.
type chanList struct { //lint:ignore U1000 for linkname
	// protects concurrent access to chans
	sync.Mutex

	// chans are indexed by the local id of the channel, which the
	// other side should send in the PeersId field.
	chans []*channel //lint:ignore U1000 for linkname

	// This is a debugging aid: it offsets all IDs by this
	// amount. This helps distinguish otherwise identical
	// server/client muxes
	offset uint32 //lint:ignore U1000 for linkname
}

// mux represents the state for the SSH connection protocol, which
// multiplexes many channels onto a single packet transport.
type mux struct { //lint:ignore U1000 for linkname
	conn     packetConn //lint:ignore U1000 for linkname
	chanList chanList   //lint:ignore U1000 for linkname

	incomingChannels chan ssh.NewChannel

	globalSentMu     sync.Mutex       //lint:ignore U1000 for linkname
	globalResponses  chan interface{} //lint:ignore U1000 for linkname
	incomingRequests chan *ssh.Request

	errCond *sync.Cond //lint:ignore U1000 for linkname
	err     error      //lint:ignore U1000 for linkname
}

type connTransport interface {
	packetConn
	getSessionID() []byte
	waitSession() error
}

// A connection represents an incoming connection.
type connection struct {
	transport connTransport
	sshConn

	// The connection protocol.
	*mux
}

type ConnectionForward struct {
	transport *net.UnixConn
	Stdin     net.Conn
	Stdout    net.Conn
}

func (c *connection) Close() error {
	return c.sshConn.conn.Close()
}

func (c *connection) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	return muxSendRequest(c.mux, name, wantReply, payload)
}

func (c *connection) OpenChannel(chanType string, extra []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	return muxOpenChannel(c.mux, chanType, extra)
}

func (c *connection) Wait() error {
	return muxWait(c.mux)
}

// sshConn provides net.Conn metadata, but disallows direct reads and
// writes.
type sshConn struct {
	conn net.Conn

	user          string
	sessionID     []byte
	clientVersion []byte
	serverVersion []byte
}

func dup(src []byte) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

func (c *sshConn) User() string {
	return c.user
}

func (c *sshConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *sshConn) Close() error {
	return c.conn.Close()
}

func (c *sshConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *sshConn) SessionID() []byte {
	return dup(c.sessionID)
}

func (c *sshConn) ClientVersion() []byte {
	return dup(c.clientVersion)
}

func (c *sshConn) ServerVersion() []byte {
	return dup(c.serverVersion)
}

// NewControlClientConn establishes an SSH connection over an OpenSSH
// ControlMaster socket c in proxy mode. The Request and NewChannel channels
// must be serviced or the connection will hang.
func NewControlClientConn(c net.Conn) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	conn := &connection{
		sshConn: sshConn{conn: c},
	}
	var err error
	if conn.transport, err = handshakeControlProxy(c); err != nil {
		return nil, nil, nil, fmt.Errorf("ssh: control proxy handshake failed; %v", err)
	}
	conn.mux = newMux(conn.transport)
	return conn, conn.mux.incomingChannels, conn.mux.incomingRequests, nil
}

// NewControlStdioForward establishes tunnel over an ControlMaster socket c in Stdio Forward mode.
func NewControlStdioForward(c *net.UnixConn, host string, port int) (*ConnectionForward, error) {
	stdin, stdout, err := handshakeControlStdioForward(c, host, port)
	if err != nil {
		return nil, fmt.Errorf("ssh: control forward handshake failed; %v", err)
	}

	return &ConnectionForward{
		transport: c,
		Stdin:     stdin,
		Stdout:    stdout,
	}, nil
}

func (m *ConnectionForward) Close() error {
	return m.transport.Close()
}

func (m *ConnectionForward) LocalAddr() net.Addr {
	return m.transport.LocalAddr()
}

func (m *ConnectionForward) RemoteAddr() net.Addr {
	return m.transport.RemoteAddr()
}

func (m *ConnectionForward) Read(b []byte) (int, error) {
	return m.Stdout.Read(b)
}

func (m *ConnectionForward) Write(b []byte) (int, error) {
	return m.Stdin.Write(b)
}

func (m *ConnectionForward) SetDeadline(t time.Time) error {
	return m.Stdin.SetReadDeadline(t)
}

func (m *ConnectionForward) SetReadDeadline(t time.Time) error {
	return m.Stdin.SetReadDeadline(t)
}

func (m *ConnectionForward) SetWriteDeadline(t time.Time) error {
	return m.Stdin.SetWriteDeadline(t)
}

const (
	muxMsgHello   = 0x00000001
	muxAliveCheck = 0x10000004
	muxCliProxy   = 0x1000000f
	muxStdioFwd   = 0x10000008
	muxSvrProxy   = 0x8000000f
	muxSFailure   = 0x80000003
)

// handshakeControlProxy attempts to establish a transport connection with an
// OpenSSH ControlMaster socket in proxy mode. For details see:
// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.mux
func handshakeControlProxy(rw io.ReadWriteCloser) (connTransport, error) {
	b := &controlBuffer{}
	b.writeUint32(muxMsgHello)
	b.writeUint32(4) // Protocol Version
	if _, err := rw.Write(b.lengthPrefixedBytes()); err != nil {
		return nil, fmt.Errorf("mux hello write failed: %v", err)
	}

	b.Reset()
	b.writeUint32(muxCliProxy)
	b.writeUint32(0) // Request ID
	if _, err := rw.Write(b.lengthPrefixedBytes()); err != nil {
		return nil, fmt.Errorf("mux client proxy write failed: %v", err)
	}

	r := controlReader{rw}
	m, err := r.next()
	if err != nil {
		return nil, fmt.Errorf("mux hello read failed: %v", err)
	}
	if m.messageType != muxMsgHello {
		return nil, fmt.Errorf("mux reply not hello")
	}
	if v, err := m.readUint32(); err != nil || v != 4 {
		return nil, fmt.Errorf("mux reply hello has bad protocol version")
	}
	m, err = r.next()
	if err != nil {
		return nil, fmt.Errorf("error reading mux server proxy: %v", err)
	}
	if m.messageType != muxSvrProxy {
		return nil, fmt.Errorf("expected server proxy response got %d", m.messageType)
	}
	return &controlProxyTransport{rw}, nil
}

func handshakeControlStdioForward(rw *net.UnixConn, host string, port int) (net.Conn, net.Conn, error) {
	// https://github.com/openssh/openssh-portable/blob/8725dbc5b5fcc3e326fc71189ef8dba4333362cc/mux.c#L2135
	// 3. Requesting passenger-mode stdio forwarding

	// A client may request the master to establish a stdio forwarding:

	// uint32	MUX_C_NEW_STDIO_FWD
	// uint32	request id
	// string	reserved
	// string	connect host
	// string	connect port (sic, it's wrong type) https://github.com/openssh/openssh-portable/blob/8725dbc5b5fcc3e326fc71189ef8dba4333362cc/mux.c#L2135

	// The client then sends its standard input and output file descriptors
	// (in that order) using Unix domain socket control messages.

	// The contents of "reserved" are currently ignored.

	// A server may reply with a MUX_S_SESSION_OPENED, a MUX_S_PERMISSION_DENIED
	// or a MUX_S_FAILURE.
	// https://github.com/openssh/openssh-portable/blob/6575859d7acb110acf408707f98ed9744ca7d692/PROTOCOL.mux#L5
	b := &controlBuffer{}
	b.writeUint32(muxMsgHello)
	b.writeUint32(4) // Protocol Version
	if _, err := rw.Write(b.lengthPrefixedBytes()); err != nil {
		return nil, nil, fmt.Errorf("mux hello write failed: %v", err)
	}
	stdin, _, _, stdinFD, err := makeSocketFromSocketPair()
	if err != nil {
		return nil, nil, err
	}
	stdout, _, _, stdoutFD, err := makeSocketFromSocketPair()
	if err != nil {
		return nil, nil, err
	}
	b.Reset()
	b.writeUint32(muxStdioFwd)
	b.writeUint32(0)  // Request ID
	b.writeString("") // Reserved
	b.writeString(host)
	b.writeUint32(uint32(port))

	if _, err := rw.Write(b.lengthPrefixedBytes()); err != nil {
		return nil, nil, fmt.Errorf("mux client forward write failed: %v", err)
	}
	err = sendFd(rw, stdinFD)
	if err != nil {
		return nil, nil, fmt.Errorf("sendFd err: %w", err)
	}
	err = sendFd(rw, stdoutFD)
	if err != nil {
		return nil, nil, fmt.Errorf("stdoutFD err: %w", err)
	}
	r := controlReader{rw}
	m, err := r.next()
	if err != nil {
		return nil, nil, fmt.Errorf("mux hello read failed: %w", err)
	}
	if m.messageType != muxMsgHello {
		return nil, nil, fmt.Errorf("mux reply not hello")
	}
	if v, err := m.readUint32(); err != nil || v != 4 {
		return nil, nil, fmt.Errorf("mux reply hello has bad protocol version")
	}
	return stdin, stdout, nil
}

func makeSocketFromSocketPair() (net.Conn, uintptr, net.Conn, uintptr, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, 0, nil, 0, err
	}

	f0 := os.NewFile(uintptr(fds[0]), "socketpair-0")
	c0, err := net.FileConn(f0)
	if err != nil {
		f0.Close()
		return nil, 0, nil, 0, err
	}
	f1 := os.NewFile(uintptr(fds[1]), "socketpair-0")
	c1, err := net.FileConn(f1)
	if err != nil {
		f0.Close()
		f1.Close()
		return nil, 0, nil, 0, err
	}

	return c0, f0.Fd(), c1, f1.Fd(), nil
}

func sendFd(conn *net.UnixConn, fd uintptr) error {
	oob := syscall.UnixRights(int(fd))
	_, _, err := conn.WriteMsgUnix([]byte{}, oob, nil)
	return err
}

// controlProxyTransport implements the connTransport interface for
// ControlMaster connections. Each controlMessage has zero length padding and
// no MAC.
type controlProxyTransport struct {
	rw io.ReadWriteCloser
}

func (p *controlProxyTransport) Close() error {
	return p.rw.Close()
}

func (p *controlProxyTransport) getSessionID() []byte {
	return nil
}

func (p *controlProxyTransport) readPacket() ([]byte, error) {
	var l uint32
	err := binary.Read(p.rw, binary.BigEndian, &l)
	if err == nil {
		buf := &bytes.Buffer{}
		_, err = io.CopyN(buf, p.rw, int64(l))
		if err == nil {
			// Discard the padding byte.
			_, _ = buf.ReadByte()
			return buf.Bytes(), nil
		}
	}
	return nil, err
}

func (p *controlProxyTransport) writePacket(controlMessage []byte) error {
	l := uint32(len(controlMessage)) + 1
	b := &bytes.Buffer{}
	_ = binary.Write(b, binary.BigEndian, &l) // controlMessage Length.
	b.WriteByte(0)                            // Padding Length.
	b.Write(controlMessage)
	_, err := p.rw.Write(b.Bytes())
	return err
}

func (p *controlProxyTransport) waitSession() error {
	return nil
}

type controlBuffer struct {
	bytes.Buffer
}

func (b *controlBuffer) writeUint32(i uint32) {
	_ = binary.Write(b, binary.BigEndian, i)
}

func (b *controlBuffer) writeString(s string) {
	_ = binary.Write(b, binary.BigEndian, uint32(len(s)))
	b.WriteString(s)
}

func (b *controlBuffer) lengthPrefixedBytes() []byte {
	b2 := &bytes.Buffer{}
	_ = binary.Write(b2, binary.BigEndian, uint32(b.Len()))
	b2.Write(b.Bytes())
	return b2.Bytes()
}

type controlMessage struct {
	body        bytes.Buffer
	messageType uint32
}

func (p controlMessage) readUint32() (uint32, error) {
	var u uint32
	err := binary.Read(&p.body, binary.BigEndian, &u)
	return u, err
}

func (p controlMessage) readString() (string, error) {
	var l uint32
	err := binary.Read(&p.body, binary.BigEndian, &l)
	if err != nil {
		return "", fmt.Errorf("error reading string length: %v", err)
	}
	b := p.body.Next(int(l))
	if len(b) != int(l) {
		return string(b), fmt.Errorf("EOF on string read")
	}
	return string(b), nil
}

type controlReader struct {
	r io.Reader
}

func (r controlReader) next() (*controlMessage, error) {
	p := &controlMessage{}
	var len uint32
	err := binary.Read(r.r, binary.BigEndian, &len)
	if err != nil {
		return nil, fmt.Errorf("error reading message length: %v", err)
	}
	_, err = io.CopyN(&p.body, r.r, int64(len))
	if err != nil {
		return nil, fmt.Errorf("error reading message payload: %v", err)
	}
	err = binary.Read(&p.body, binary.BigEndian, &p.messageType)
	if err != nil {
		return nil, fmt.Errorf("error reading message type: %v", err)
	}
	if p.messageType == muxSFailure {
		reason, _ := p.readString()
		return nil, fmt.Errorf("server failure: '%s'", reason)
	}
	return p, nil
}
