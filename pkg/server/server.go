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
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	gcmd "github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/devconf"
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
	hostParams   map[string]hostParams
	hostParamsMu sync.Mutex
}

type hostParams struct {
	port   int
	device string
	creds  credentials.Credentials
}

func (m *hostParams) GetCredentials() credentials.Credentials {
	return m.creds
}

func (m *hostParams) GetDevice() string {
	return m.device
}

func (m *hostParams) GetPort() int {
	return m.port
}

func makeHostParams(port int, device string, creds *pb.Credentials) hostParams {
	var credsParsed credentials.Credentials
	if creds != nil {
		credsParsed = BuildCreds(creds.GetLogin(), creds.GetPassword(), false, nil)
	}
	return hostParams{
		port:   port,
		device: device,
		creds:  credsParsed,
	}
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

func (m *Server) makeDevice(hostname string, params hostParams, add func(op gtrace.Operation, data []byte), logger *zap.Logger) (device.Device, error) {
	c := m.creds // global
	paramCreds := params.GetCredentials()
	if paramCreds != nil {
		c = paramCreds
	}
	deviceType := params.GetDevice()
	streamerOpts := []ssh.StreamerOption{ssh.WithLogger(logger), ssh.WithTrace(add)}
	hostOpts := []ssh.EndpointOption{}
	port := params.GetPort()
	if port > 0 {
		hostOpts = append(hostOpts, ssh.WithPort(port))
	}
	host := ssh.NewEndpoint(hostname, hostOpts...)
	connector := ssh.NewStreamer(host, c, streamerOpts...)

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
	params, ok := m.getHostParams(firstCmd.GetHost())
	if !ok {
		return status.Errorf(codes.Internal, "params are not set")
	}

	devInited, err := m.makeDevice(firstCmd.GetHost(), params, devTraceMulti.Add, logger)
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
		if cmd.Host != firstCmd.Host {
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

func (m *Server) SetupHostParams(ctx context.Context, hostParams *pb.HostParams) (*emptypb.Empty, error) {
	m.log.Debug("SetupHostParams", zap.Any("device", hostParams))
	port := hostParams.GetPort()
	m.updateHostParams(hostParams.GetHost(), makeHostParams(int(port), hostParams.GetDevice(), hostParams.GetCredentials()))
	return &emptypb.Empty{}, nil
}

func (m *Server) updateHostParams(hostname string, params hostParams) {
	m.hostParamsMu.Lock()
	defer m.hostParamsMu.Unlock()
	m.hostParams[hostname] = params
}

func (m *Server) getHostParams(hostname string) (params hostParams, ok bool) {
	m.hostParamsMu.Lock()
	defer m.hostParamsMu.Unlock()
	params, ok = m.hostParams[hostname]
	return params, ok
}

func (m *Server) Download(ctx context.Context, req *pb.FileDownloadRequest) (*pb.FilesResult, error) {
	logger := m.log.With(zap.String("host", req.GetHost()))
	m.log.Info("downloads")
	paths := req.GetPaths()
	if len(paths) == 0 {
		return nil, errors.New("empty paths")
	}
	params, ok := m.getHostParams(req.GetHost())
	if !ok {
		return nil, status.Errorf(codes.Internal, "params are not set")
	}
	devInited, err := m.makeDevice(req.GetHost(), params, nil, logger)
	if err != nil {
		logger.Debug("download error", zap.Error(err))
		return nil, status.Error(codes.Internal, fmt.Sprintf("download error: %s", err))
	}
	err = devInited.Connect(ctx)
	if err != nil {
		logger.Debug("download error", zap.Error(err))
		return nil, status.Error(codes.Internal, fmt.Sprintf("download error: %s", err))
	}

	downloadRes, err := devInited.Download(paths)
	if err != nil {
		logger.Debug("download error", zap.Error(err))
		return nil, status.Error(codes.Internal, fmt.Sprintf("download error: %s", err))
	}

	res := makeFilesResult(downloadRes)
	return res, nil
}

func (m *Server) Upload(ctx context.Context, req *pb.FileUploadRequest) (*emptypb.Empty, error) {
	logger := m.log.With(zap.String("host", req.GetHost()))
	logger.Info("upload")
	params, ok := m.getHostParams(req.GetHost())
	if !ok {
		return nil, status.Errorf(codes.Internal, "params are not set")
	}
	devInited, err := m.makeDevice(req.GetHost(), params, nil, logger)
	if err != nil {
		return nil, err
	}
	uploadFiles := makeFilesUpload(req.GetFiles())
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
		hostParams:                 map[string]hostParams{},
		hostParamsMu:               sync.Mutex{},
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
	}
	if logger != nil {
		opts = append(opts, credentials.WithLogger(logger))
	}
	if enableAgent {
		opts = append(opts, credentials.WithSSHAgentSocket(credentials.GetDefaultAgentSocket()))
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

func MakeFileResult(path string, file streamer.File) *pb.FileData {
	res := &pb.FileData{
		Path:   path,
		Data:   nil,
		Status: pb.FileStatus_FileStatus_notset,
	}
	if file.Err != nil {
		if strings.Contains(file.Err.Error(), "file does not exist") {
			res.Status = pb.FileStatus_FileStatus_not_found
		} else {
			res.Status = pb.FileStatus_FileStatus_error
		}
	} else if file.Mode.IsDir() {
		res.Status = pb.FileStatus_FileStatus_is_dir
	} else {
		res.Status = pb.FileStatus_FileStatus_ok
		res.Data = file.Data
	}
	return res
}

func makeFilesUpload(files []*pb.FileData) map[string]streamer.File {
	res := map[string]streamer.File{}
	for _, file := range files {
		res[file.GetPath()] = streamer.NewFileData(file.GetData())
	}
	return res
}

func makeFilesResult(files map[string]streamer.File) *pb.FilesResult {
	res := pb.FilesResult{
		Files: []*pb.FileData{},
	}
	for path, file := range files {
		p := MakeFileResult(path, file)
		res.Files = append(res.Files, p)
	}
	return &res
}
