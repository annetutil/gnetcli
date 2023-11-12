/*
Package server implements GRPC-server upon gnetcli library.
*/
package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"sync"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/annetutil/gnetcli/internal/devconf"
	gcmd "github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/device"
	"github.com/annetutil/gnetcli/pkg/device/genericcli"
	"github.com/annetutil/gnetcli/pkg/expr"
	pb "github.com/annetutil/gnetcli/pkg/server/proto"
	"github.com/annetutil/gnetcli/pkg/streamer"
	"github.com/annetutil/gnetcli/pkg/streamer/ssh"
	gtrace "github.com/annetutil/gnetcli/pkg/trace"
)

const cmdTraceLimit = 1000

var errEmptyCmd = errors.New("empty cmd")
var errEmptyHost = errors.New("empty host")
var errWrongReadTimeout = errors.New("wrong read timeout")
var errWrongCmdTimeout = errors.New("wrong cmd timeout")
var errDevDuplicate = errors.New("duplicated device type")

type Server struct {
	pb.UnimplementedGnetcliServer
	log          *zap.Logger
	creds        credentials.Credentials
	deviceMaps   map[string]func(streamer.Connector) device.Device
	deviceMapsMu sync.Mutex
}

type Option func(*Server)

func WithLogger(logger *zap.Logger) Option {
	return func(h *Server) {
		h.log = logger
	}
}

func WithCredentials(creds credentials.Credentials) Option {
	return func(h *Server) {
		h.creds = creds
	}
}

func (m *Server) makeDevice(hostname string, deviceType string, creds *pb.Credentials, add func(op gtrace.Operation, data []byte), logger *zap.Logger) (device.Device, error) {
	c := m.creds
	if creds != nil {
		c = BuildCreds(creds.GetLogin(), creds.GetPassword(), false, m.log)
	}
	connector := ssh.NewStreamer(hostname, c, ssh.WithLogger(logger), ssh.WithTrace(add))
	devFab, ok := m.deviceMaps[deviceType]
	if !ok {
		return nil, fmt.Errorf("unknown device %v", deviceType)
	}
	devInited := devFab(connector)
	return devInited, nil
}

func (m *Server) ExecChat(stream pb.Gnetcli_ExecChatServer) error {
	authData, ok := getAuthFromContext(stream.Context())
	if !ok {
		return errors.New("empty auth")
	}
	logger := zap.New(m.log.Core()).With(zap.String("login", authData.GetUser()))
	m.log.Info("start chat")
	firstCmd, err := stream.Recv()
	if err != nil {
		if err == io.EOF {
			return nil
		}
		return status.Errorf(codes.Internal, err.Error())
	}
	err = validateCmd(firstCmd)
	if err != nil {
		return status.Errorf(codes.Internal, err.Error())
	}
	devTraceMulti := NewMultiTrace()
	devTrace := gtrace.NewTraceLimited(cmdTraceLimit)
	devTraceMulti.AddTrace(devTrace)

	logger = logger.With(zap.String("host", firstCmd.GetHost()))
	devInited, err := m.makeDevice(firstCmd.GetHost(), firstCmd.GetDevice(), firstCmd.GetCredentials(), devTraceMulti.Add, logger)
	if err != nil {
		return status.Errorf(codes.Internal, err.Error())
	}
	ctx := stream.Context()
	logger.Info("connect")
	err = devInited.Connect(ctx)
	if err != nil {
		return status.Errorf(codes.Internal, err.Error())
	}

	cmd := firstCmd
	for {
		var traceRes []*pb.CMDTraceItem
		var cmdTr gtrace.Trace
		traceIndex := -1
		if cmd.GetTrace() {
			cmdTr = gtrace.NewTraceLimited(cmdTraceLimit)
			traceIndex = devTraceMulti.AddTrace(cmdTr)
		}

		chatCmd := makeGnetcliCmd(cmd)
		res, err := devInited.Execute(chatCmd)
		start := time.Now()
		logger.Debug("executed", zap.String("cmd", cmd.String()), zap.Duration("duration", time.Since(start)), zap.Error(err))

		if cmd.GetTrace() {
			traceRes = gnetcliTraceToTrace(cmdTr)
			err := devTraceMulti.DelTrace(traceIndex)
			if err != nil {
				return status.Errorf(codes.Internal, err.Error())
			}
		}
		err = stream.Send(makeServerRes(cmd, res, traceRes))
		if err != nil {
			return status.Errorf(codes.Internal, err.Error())
		}
		cmd, err = stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return status.Errorf(codes.Internal, err.Error())
		}
		err = validateCmd(cmd)
		if err != nil {
			return status.Errorf(codes.Internal, err.Error())
		}
		logger.Debug("recv", zap.Any("cmd", cmd))
		if cmd.Host != firstCmd.Host || cmd.Device != firstCmd.Device {
			return status.Errorf(codes.Internal, fmt.Errorf("host is not the same %v vs %v", firstCmd, cmd).Error())
		}
	}
}

func (m *Server) Exec(ctx context.Context, cmd *pb.CMD) (*pb.CMDResult, error) {
	stream := execChatWrapper{
		cmd:  cmd,
		seen: false,
		ctx:  ctx,
		res:  nil,
	}
	err := m.ExecChat(&stream)
	if err != nil {
		return nil, err
	}
	return stream.res, nil
}

type execChatWrapper struct {
	cmd  *pb.CMD
	seen bool
	ctx  context.Context
	res  *pb.CMDResult
}

func (m *execChatWrapper) Send(result *pb.CMDResult) error {
	m.res = result
	return nil
}

func (m *execChatWrapper) Recv() (*pb.CMD, error) {
	if !m.seen {
		m.seen = true
		return m.cmd, nil
	} else {
		return nil, io.EOF
	}
}

func (m *execChatWrapper) SetHeader(md metadata.MD) error {
	return errors.New("not implemented")
}

func (m *execChatWrapper) SendHeader(md metadata.MD) error {
	return errors.New("not implemented")
}

func (m *execChatWrapper) SetTrailer(md metadata.MD) {
}

func (m *execChatWrapper) Context() context.Context {
	return m.ctx
}

func (m *execChatWrapper) SendMsg(msg interface{}) error {
	return errors.New("not implemented")
}

func (m *execChatWrapper) RecvMsg(msg interface{}) error {
	return errors.New("not implemented")
}

func makeNewDevice(dev *pb.Device) (*genericcli.GenericCLI, error) {
	promptExpr := dev.GetPromptExpression()
	_, err := regexp.Compile(promptExpr)
	if err != nil {
		return nil, fmt.Errorf("prompt expression error %w", err)
	}

	errorExpr := dev.GetErrorExpression()
	if len(errorExpr) > 0 {
		_, err := regexp.Compile(errorExpr)
		if err != nil {
			return nil, fmt.Errorf("error expression error %w", err)
		}
	} else {
		errorExpr = "$.^" // must not match anything
	}
	opts := []genericcli.GenericCLIOption{
		genericcli.WithSFTPEnabled(),
	}
	pagerExpression := dev.GetPagerExpression()
	if len(pagerExpression) > 0 {
		_, err := regexp.Compile(pagerExpression)
		if err != nil {
			return nil, fmt.Errorf("pager expression error %w", err)
		}
		opts = append(opts, genericcli.WithPager(expr.NewSimpleExprLast200(pagerExpression)))
	}

	cli := genericcli.MakeGenericCLI(
		expr.NewSimpleExprLast200(promptExpr),
		expr.NewSimpleExprLast200(errorExpr),
		opts...,
	)
	return &cli, nil
}

func (m *Server) AddDevice(ctx context.Context, device *pb.Device) (*pb.DeviceResult, error) {
	m.log.Debug("add device", zap.Any("device", device))
	devName := device.GetName()
	m.deviceMapsMu.Lock()
	defer m.deviceMapsMu.Unlock()
	_, ok := m.deviceMaps[devName]
	if ok {
		return nil, errDevDuplicate
	}
	gCli, err := makeNewDevice(device)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	m.deviceMaps[devName] = devconf.GenericCLIDevToDev(gCli)

	return &pb.DeviceResult{
		Res:   pb.DeviceResultStatus_Device_ok,
		Error: "",
	}, nil
}

func (m *Server) Downloads(ctx context.Context, req *pb.FileDownloadRequest) (*pb.FilesResult, error) {
	logger := m.log.With(zap.String("host", req.GetHost()))
	m.log.Info("downloads")
	devInited, err := m.makeDevice(req.GetHost(), req.GetDevice(), req.GetCredentials(), nil, logger)
	if err != nil {
		logger.Debug("download error", zap.Error(err))
		return nil, status.Error(codes.Internal, fmt.Sprintf("download error: %s", err))
	}
	err = devInited.Connect(ctx)
	if err != nil {
		logger.Debug("download error", zap.Error(err))
		return nil, status.Error(codes.Internal, fmt.Sprintf("download error: %s", err))
	}
	path := req.GetPath()
	if len(path) == 0 {
		return nil, errors.New("empty path")
	}
	downloadRes, err := devInited.Download([]string{path})
	if err != nil {
		logger.Debug("download error", zap.Error(err))
		return nil, status.Error(codes.Internal, fmt.Sprintf("download error: %s", err))
	}

	res := MakeFilesResult(downloadRes)
	return res, nil
}

func (m *Server) Upload(ctx context.Context, req *pb.FileUploadRequest) (*emptypb.Empty, error) {
	logger := m.log.With(zap.String("upload", req.GetHost()))
	m.log.Info("downloads")
	devInited, err := m.makeDevice(req.GetHost(), req.GetDevice(), req.GetCredentials(), nil, logger)
	if err != nil {
		return nil, err
	}
	uploadFile := streamer.NewFileData(req.GetData())
	uploadFiles := map[string]streamer.File{req.GetPath(): uploadFile}
	err = devInited.Upload(uploadFiles)
	return &emptypb.Empty{}, err
}

func New(opts ...Option) *Server {
	s := &Server{
		UnimplementedGnetcliServer: pb.UnimplementedGnetcliServer{},
		log:                        zap.NewNop(),
		creds:                      nil,
		deviceMapsMu:               sync.Mutex{},
		deviceMaps:                 nil,
	}
	for _, opt := range opts {
		opt(s)
	}
	s.deviceMaps = devconf.InitDefaultDeviceMapping(s.log)
	return s
}

func gnetcliTraceToTrace(tr gtrace.Trace) []*pb.CMDTraceItem {
	var traceRes []*pb.CMDTraceItem
	for _, v := range tr.List() {
		traceRes = append(traceRes, &pb.CMDTraceItem{Operation: pb.TraceOperation(v.GetOperation()) + 1, Data: v.GetData()})
	}
	return traceRes
}

func makeGnetcliCmd(cmd *pb.CMD) gcmd.Cmd {
	return gcmd.NewCmd(cmd.GetCmd())
}

func makeServerRes(cmd *pb.CMD, cmdRes gcmd.CmdRes, tr []*pb.CMDTraceItem) *pb.CMDResult {
	res := pb.CMDResult{
		Out:      nil,
		OutStr:   "",
		Error:    nil,
		ErrorStr: "",
		Trace:    nil,
		Status:   int32(cmdRes.Status()),
	}
	if cmd.GetTrace() {
		res.Trace = tr
	}
	if cmd.GetStringResult() {
		res.OutStr = string(cmdRes.Output())
		res.ErrorStr = string(cmdRes.Error())
	} else {
		res.Out = cmdRes.Output()
		res.Error = cmdRes.Error()
	}
	return &res
}

func validateCmd(cmd *pb.CMD) error {
	if len(cmd.GetCmd()) == 0 {
		return errEmptyCmd
	}
	if len(cmd.GetHost()) == 0 {
		return errEmptyHost
	}
	if cmd.GetCmdTimeout() < 0 || math.IsNaN(cmd.GetCmdTimeout()) {
		return errWrongReadTimeout
	}
	if cmd.GetReadTimeout() < 0 || math.IsNaN(cmd.GetReadTimeout()) {
		return errWrongCmdTimeout
	}
	return nil
}

func BuildCreds(login, password string, enableAgent bool, logger *zap.Logger) credentials.Credentials {
	if len(login) == 0 {
		newLogin := credentials.GetLogin()
		login = newLogin
	}

	opts := []credentials.CredentialsOption{
		credentials.WithUsername(login),
		credentials.WithLogger(logger),
	}
	if enableAgent {
		opts = append(opts, credentials.WithSSHAgent())
	}
	if len(password) > 0 {
		opts = append(opts, credentials.WithPassword(credentials.Secret(password)))
	}
	creds := credentials.NewSimpleCredentials(opts...)
	return creds
}

func BuildEmptyCreds(logger *zap.Logger) credentials.Credentials {
	opts := []credentials.CredentialsOption{
		credentials.WithLogger(logger),
	}
	creds := credentials.NewSimpleCredentials(opts...)
	return creds
}

func MakeFileResult(path string, f streamer.File) *pb.FileResult {
	return &pb.FileResult{
		Path: path,
		Data: f.Data,
	}
}

func MakeFilesResult(files map[string]streamer.File) *pb.FilesResult {
	res := pb.FilesResult{
		Files: []*pb.FileResult{},
	}
	for path, file := range files {
		if file.Err != nil {
			continue
		}
		if file.Mode.IsDir() {
			continue
		}
		p := MakeFileResult(path, file)
		res.Files = append(res.Files, p)
	}
	return &res
}
