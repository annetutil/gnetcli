/*
Package netconf implements netconf.
*/
package netconf

import (
	"context"
	"encoding/xml"
	"fmt"
	"strconv"
	"sync/atomic"

	"go.uber.org/zap"
	"golang.org/x/exp/slices"

	gcmd "github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/device"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/streamer"
)

const (
	eom             = "]]>]]>"
	netconfVer10    = 10
	netconfVer11    = 11
	netconfVer11Cap = "urn:ietf:params:netconf:base:1.1"
	netconfVer10Cap = "urn:ietf:params:netconf:base:1.0"
	netconfXMLBegin = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
	netconfXMLNS    = "urn:ietf:params:xml:ns:netconf:base:1.0"
)

const AuxServerCapabilities = "NetconfServerCapabilities"

type Node struct {
	XMLName xml.Name
	Content []byte `xml:",innerxml"`
	Nodes   []Node `xml:",any"`
}

type Data struct {
	XMLName xml.Name `xml:"data"`
	Content []byte   `xml:",innerxml"`
	Nodes   []Node   `xml:",any"`
}

type RPCReply struct {
	XMLName   xml.Name `xml:"rpc-reply"`
	RPCError  RPCError `xml:"rpc-error"`
	Data      Data     `xml:"data"`
	MessageID string   `xml:"message-id,attr"`
	Content   []byte   `xml:",innerxml"`
	Nodes     []Node   `xml:",any"`
}

type RPCError struct {
	XMLName       xml.Name `xml:"rpc-error"`
	ErrorType     string   `xml:"error-type"`
	ErrorTag      string   `xml:"error-tag"`
	ErrorSeverity string   `xml:"error-severity"`
	ErrorPath     string   `xml:"error-path"`
	ErrorMessage  string   `xml:"error-message"`
	//ErrorInfo     string   `xml:"error-info"`
}

type Capabilities struct {
	XMLName      xml.Name `xml:"capabilities"`
	Capabilities []string `xml:"capability"`
}

type Hello struct {
	XMLName   xml.Name     `xml:"hello"`
	Xmlns     string       `xml:"xmlns,attr"`
	Hello     Capabilities `xml:"capabilities"`
	SessionID string       `xml:"session-id,omitempty"`
}

type NetconfDevice struct {
	connector          streamer.Connector
	netconfVer         int
	sessionID          string
	serverCapabilities []string
	clientCapabilities []string
	messageID          uint64
	log                *zap.Logger
}

var _ device.Device = (*NetconfDevice)(nil)

func (m *NetconfDevice) GetAux() map[string]any {
	res := map[string]any{}
	res[AuxServerCapabilities] = m.GetServerCapabilities()
	return res
}

func (m *NetconfDevice) Upload(paths map[string]streamer.File) error {
	return device.ErrorStreamerNotSupportedByDevice
}

func (m *NetconfDevice) Download(paths []string) (map[string]streamer.File, error) {
	return nil, device.ErrorStreamerNotSupportedByDevice
}

type DeviceOption func(*NetconfDevice)

func WithLogger(l *zap.Logger) DeviceOption {
	return func(h *NetconfDevice) {
		h.log = l
	}
}

func WithCapabilities(caps []string) DeviceOption {
	return func(h *NetconfDevice) {
		h.clientCapabilities = append(h.clientCapabilities, caps...)
	}
}

func BindDeviceOpts(fn func(connection streamer.Connector, opts ...DeviceOption) device.Device, opts ...DeviceOption) func(connection streamer.Connector) device.Device {
	return func(connection streamer.Connector) device.Device {
		return fn(connection, opts...)
	}
}

func NewDevice(connection streamer.Connector, opts ...DeviceOption) device.Device {
	res := &NetconfDevice{
		connector:          connection,
		netconfVer:         0,
		sessionID:          "",
		clientCapabilities: []string{},
		serverCapabilities: []string{},
		messageID:          0,
		log:                zap.NewNop(),
	}
	for _, opt := range opts {
		opt(res)
	}
	return res
}

func (m *NetconfDevice) Connect(ctx context.Context) (err error) {
	err = m.connector.Init(ctx)
	if err != nil {
		return err
	}
	res, err := m.connector.ReadTo(ctx, expr.NewSimpleExprLast20(eom))
	if err != nil {
		return err
	}
	var hello Hello
	err = xml.Unmarshal(res.GetBefore(), &hello)
	if err != nil {
		return err
	}
	capabilities := []string{netconfVer10Cap, netconfVer11Cap}
	capabilities = append(capabilities, m.clientCapabilities...)
	p := Hello{
		XMLName: xml.Name{},
		Xmlns:   netconfXMLNS,
		Hello: Capabilities{
			XMLName: xml.Name{
				Space: "",
				Local: "",
			},
			Capabilities: capabilities,
		},
		SessionID: "",
	}

	capabilitiesXML, _ := xml.MarshalIndent(p, "", "")
	err = m.write([]byte(netconfXMLBegin + string(capabilitiesXML)))
	if err != nil {
		return fmt.Errorf("write error %w", err)
	}

	netconfVer := netconfVer10
	for _, capability := range hello.Hello.Capabilities {
		if capability == netconfVer11Cap {
			netconfVer = netconfVer11
		}
	}
	m.netconfVer = netconfVer
	m.sessionID = hello.SessionID
	m.serverCapabilities = hello.Hello.Capabilities
	return nil

}

func (m *NetconfDevice) Close() {
	m.connector.Close()
}

func (m *NetconfDevice) GetServerCapabilities() []string {
	return slices.Clone(m.serverCapabilities)
}

func (m *NetconfDevice) formatCmd(command gcmd.Cmd) []byte {
	messageID := atomic.AddUint64(&m.messageID, 1)
	commandVal := []byte(netconfXMLBegin)
	rpcHead := fmt.Sprintf("<rpc xmlns=\"%s\" message-id=\"%d\">", netconfXMLNS, messageID)
	commandVal = append(commandVal, []byte(rpcHead)...)
	commandVal = append(commandVal, command.Value()...)
	commandVal = append(commandVal, []byte("</rpc>")...)
	return commandVal
}

func (m *NetconfDevice) Execute(command gcmd.Cmd) (gcmd.CmdRes, error) {
	var res []byte
	var err error
	ctx := context.Background()
	if cmdTimeout := command.GetCmdTimeout(); cmdTimeout > 0 {
		newCtx, cancel := context.WithTimeout(ctx, cmdTimeout)
		ctx = newCtx
		defer cancel()
	}

	commandVal := m.formatCmd(command)

	if m.netconfVer == netconfVer10 {
		res, err = m.cmd10(ctx, commandVal)
	} else {
		res, err = m.cmd11(ctx, commandVal)
	}
	if err != nil {
		return nil, err
	}
	var reply RPCReply
	err = xml.Unmarshal(res, &reply)
	if err != nil {
		return nil, fmt.Errorf("xml unmarshal error %w", err)
	}
	err = m.checkError(reply)
	status := 0
	errRet := ""
	if err != nil {
		status = 1
		errRet = err.Error()
	}
	ret := gcmd.NewCmdResFull(res, []byte(errRet), status, map[string]interface{}{"root": reply})
	return ret, nil
}

func (m *NetconfDevice) cmd11(ctx context.Context, command []byte) ([]byte, error) {
	err := m.writeChunked(command)
	if err != nil {
		return nil, err
	}
	output, err := m.readChunked(ctx)
	if err != nil {
		return nil, err
	}

	return output, nil
}

func (m *NetconfDevice) cmd10(ctx context.Context, command []byte) ([]byte, error) {
	err := m.write(command)
	if err != nil {
		return nil, err
	}

	res, err := m.connector.ReadTo(ctx, expr.NewSimpleExprLast20(eom))
	if err != nil {
		return nil, err
	}
	return res.GetBefore(), nil
}

func (m *NetconfDevice) writeChunked(data []byte) error {
	_ = m.connector.Write([]byte("\n#" + strconv.Itoa(len(data)) + "\n"))
	_ = m.connector.Write(data)
	_ = m.connector.Write([]byte("\n##\n"))
	return nil
}

func (m *NetconfDevice) write(data []byte) error {
	_ = m.connector.Write(data)
	_ = m.connector.Write([]byte("]]>]]>"))
	return nil
}

// https://datatracker.ietf.org/doc/html/rfc6242#section-4.2
func (m *NetconfDevice) readChunked(ctx context.Context) ([]byte, error) {
	buffer := []byte{}
	for {
		// Chunked-Message = 1*chunk end-of-chunks
		//
		// chunk           = LF HASH chunk-size LF
		//                   chunk-data
		// chunk-size      = 1*DIGIT1 0*DIGIT
		// chunk-data      = 1*OCTET
		//
		// end-of-chunks   = LF HASH HASH LF
		//
		// DIGIT1          = %x31-39
		// DIGIT           = %x30-39
		// HASH            = %x23
		// LF              = %x0A
		// OCTET           = %x00-FF
		sizeLine, err := m.connector.ReadTo(ctx, expr.NewSimpleExprFirst200(`\n#(?P<size>[1-9]\d*|#)\n`))
		if err != nil {
			return nil, fmt.Errorf("chunk size read error %w", err)
		}
		size := string(sizeLine.GetMatchedGroups()["size"])
		m.log.Debug("sizeLine", zap.String("size", size))
		if size == "#" { //end-of-chunks
			buffer = append(buffer, sizeLine.GetBefore()...)
			return buffer, nil
		}
		readSize, err := strconv.Atoi(size)
		if err != nil {
			return nil, fmt.Errorf("chunk size parse error %w", err)
		}
		chunkData, err := m.connector.Read(ctx, readSize)
		if err != nil {
			return nil, err
		}
		buffer = append(buffer, chunkData...)
	}
}

func (m *NetconfDevice) checkError(reply RPCReply) error {
	if len(reply.RPCError.ErrorTag) > 0 {
		return fmt.Errorf("xml error %v", reply.RPCError)
	}
	return nil
}
