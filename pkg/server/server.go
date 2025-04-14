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
	"net/netip"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
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

type ExecErrorType string

const (
	ErrorTypeEOF     ExecErrorType = "error_eof"
	ErrorTypeUnknown ExecErrorType = "error_unknown"
)

type Server struct {
	pb.UnimplementedGnetcliServer
	log          *zap.Logger
	deviceMaps   map[string]func(streamer.Connector) device.Device
	deviceMapsMu sync.Mutex
	hostParams   map[string]hostParams
	hostParamsMu sync.Mutex
	devAuthApp   authApp
}

type hostParams struct {
	port        int
	device      string
	creds       credentials.Credentials
	ip          netip.Addr
	proxyJump   string
	controlPath string
	host        string
}

func makeGRPCDeviceExecError(err error) error {
	reason := ErrorTypeUnknown
	if errors.Is(err, &streamer.EOFException{}) {
		reason = ErrorTypeEOF
	}
	msg := err.Error()
	st := status.New(codes.Internal, msg)
	rv, _ := st.WithDetails(
		&errdetails.ErrorInfo{
			Reason:   string(reason),
			Metadata: map[string]string{"err": err.Error()},
		},
	)
	return rv.Err()
}

func NewHostParams(creds credentials.Credentials, device string, ip netip.Addr, port int, proxyJump, controlPath, host string) hostParams {
	return hostParams{
		port:        port,
		device:      device,
		creds:       creds,
		ip:          ip,
		proxyJump:   proxyJump,
		controlPath: controlPath,
		host:        host,
	}
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

func (m *hostParams) GetIP() netip.Addr {
	return m.ip
}

func makeHostConnectionParams(params *pb.HostParams) (netip.Addr, int, error) {
	addr := params.GetIp()
	ip := netip.Addr{}
	if len(addr) > 0 {
		r, err := netip.ParseAddr(addr)
		if err != nil {
			return netip.Addr{}, 0, err
		}
		ip = r
	}
	return ip, int(params.GetPort()), nil
}

type Option func(*Server)

func WithLogger(logger *zap.Logger) Option {
	return func(h *Server) {
		h.log = logger
	}
}

func (m *Server) makeConnectArg(hostname string, params hostParams) (string, int) {
	host := hostname
	if params.GetIP().IsValid() {
		host = params.GetIP().String()
	}
	var port int64 = 0
	if params.port > 0 {
		port = int64(params.port)
	}
	return host, int(port)
}

func (m *Server) makeDevice(hostname string, params hostParams, add func(op gtrace.Operation, data []byte), logger *zap.Logger) (device.Device, error) {
	var creds credentials.Credentials
	paramCreds := params.GetCredentials()
	if paramCreds != nil {
		creds = paramCreds
	} else {
		defcreds, err := m.devAuthApp.Get(hostname)
		if err != nil {
			return nil, err
		}
		creds = defcreds
	}
	deviceType := params.GetDevice()
	streamerOpts := []ssh.StreamerOption{ssh.WithLogger(logger), ssh.WithTrace(add)}
	connHost, port := m.makeConnectArg(hostname, params)
	if port > 0 {
		streamerOpts = append(streamerOpts, ssh.WithPort(port))
	}
	if params.proxyJump != "" {
		jumpHostParams, err := m.getHostParams(params.proxyJump, &pb.HostParams{})
		if err != nil {
			return nil, fmt.Errorf("unable to get host params for ssh tunnel to %s:%w", params.proxyJump, err)
		}
		opts := []ssh.SSHTunnelOption{ssh.SSHTunnelWithLogger(logger)}
		if len(jumpHostParams.controlPath) > 0 {
			opts = append(opts, ssh.SSHTunnelWithControlFIle(jumpHostParams.controlPath))
		}
		connHost = params.host
		tun := ssh.NewSSHTunnel(params.proxyJump, jumpHostParams.GetCredentials(), opts...)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err = tun.CreateConnect(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to open ssh tunnel to %s:%w", params.proxyJump, err)
		}
		streamerOpts = append(streamerOpts, ssh.WithSSHTunnel(tun))
	}
	if params.controlPath != "" {
		streamerOpts = append(streamerOpts, ssh.WithSSHControlFIle(params.controlPath))
	}
	connector := ssh.NewStreamer(connHost, creds, streamerOpts...)
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
		return errors.New("empty auth in exec chat")
	}
	logger := zap.New(m.log.Core()).With(zap.String("cmd_login", authData.GetUser()))
	logger.Info("start chat")
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

	logger = logger.With(zap.String("cmd_host", firstCmd.GetHost()))
	params, err := m.getHostParams(firstCmd.GetHost(), firstCmd.GetHostParams())
	if err != nil {
		return status.Errorf(codes.Internal, err.Error())
	}

	devInited, err := m.makeDevice(firstCmd.GetHost(), params, devTraceMulti.Add, logger)
	if err != nil {
		return status.Errorf(codes.Internal, err.Error())
	}
	ctx, cancel := context.WithTimeout(stream.Context(), 20*time.Second)
	defer cancel()
	logger.Info("connect")
	err = devInited.Connect(ctx)
	if err != nil {
		return status.Errorf(codes.Internal, err.Error())
	}
	defer devInited.Close()

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
		if err != nil {
			return makeGRPCDeviceExecError(err)
		}
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
		opts = append(opts, genericcli.WithPager(expr.NewSimpleExprLast200().FromPattern(pagerExpression)))
	}

	cli := genericcli.MakeGenericCLI(
		expr.NewSimpleExprLast200().FromPattern(promptExpr),
		expr.NewSimpleExprLast200().FromPattern(errorExpr),
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

func (m *Server) SetupHostParams(ctx context.Context, cmdHostParams *pb.HostParams) (*emptypb.Empty, error) {
	m.log.Debug("SetupHostParams", zap.Any("device", cmdHostParams))
	ip, port, err := makeHostConnectionParams(cmdHostParams)
	if err != nil {
		return nil, err
	}
	params := NewHostParams(nil, cmdHostParams.GetDevice(), ip, port, "", "", "")
	m.updateHostParams(cmdHostParams.GetHost(), params)
	return &emptypb.Empty{}, nil
}

func (m *Server) updateHostParams(hostname string, params hostParams) {
	m.hostParamsMu.Lock()
	defer m.hostParamsMu.Unlock()
	m.hostParams[hostname] = params
}

func (m *Server) getHostParams(hostname string, cmdParams *pb.HostParams) (hostParams, error) {
	// from config
	defaultCreds, err := m.devAuthApp.Get(hostname)
	if err != nil {
		return hostParams{}, err
	}
	defaultHostParams, err := m.devAuthApp.GetHostParams(hostname, cmdParams)
	if err != nil {
		return hostParams{}, err
	}

	// from GRPC calls
	var localParams *hostParams
	if localParamsVal, ok := m.hostParams[hostname]; ok {
		localParams = &localParamsVal
	}

	// from current GRPC call arg
	var cmdHostParams *hostParams
	if cmdParams != nil {
		ip, port, err := makeHostConnectionParams(cmdParams)
		if err != nil {
			return hostParams{}, err
		}
		cmdCreds := cmdParams.GetCredentials()
		var credsParsed credentials.Credentials
		if cmdCreds != nil {
			creds, err := BuildCreds(cmdParams.GetHost(), cmdCreds.GetLogin(), cmdCreds.GetPassword(), false, "", nil)
			if err != nil {
				return hostParams{}, err
			}
			credsParsed = creds
		}
		cmdHostParams = &hostParams{
			port:   port,
			device: cmdParams.Device,
			creds:  credsParsed,
			ip:     ip,
		}
	}
	var res hostParams
	// merging
	if cmdHostParams != nil {
		res = *cmdHostParams
		if res.creds == nil { // creds not in cmdParams
			if localParams != nil && localParams.creds != nil {
				res.creds = localParams.creds
			} else {
				res.creds = defaultCreds
			}
		}
	} else if localParams != nil {
		res = *localParams
		if res.creds == nil {
			res.creds = defaultCreds
		}
	} else {
		res = hostParams{
			port:   0,
			device: cmdParams.Device,
			creds:  defaultCreds,
			ip:     netip.Addr{},
		}
	}
	// proxyJump only supported in defaultHostParams
	if defaultHostParams.proxyJump != "" {
		res.proxyJump = defaultHostParams.proxyJump
		res.host = defaultHostParams.host
	}
	if defaultHostParams.controlPath != "" {
		res.controlPath = defaultHostParams.controlPath
	}
	return res, nil
}

func (m *Server) Download(ctx context.Context, req *pb.FileDownloadRequest) (*pb.FilesResult, error) {
	logger := m.log.With(zap.String("host", req.GetHost()))
	m.log.Info("downloads")
	paths := req.GetPaths()
	if len(paths) == 0 {
		return nil, errors.New("empty paths")
	}
	params, err := m.getHostParams(req.GetHost(), req.GetHostParams())
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
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
	paths := req.GetFiles()
	if len(paths) == 0 {
		return nil, errors.New("empty paths")
	}
	params, err := m.getHostParams(req.GetHost(), req.GetHostParams())
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	devInited, err := m.makeDevice(req.GetHost(), params, nil, logger)
	if err != nil {
		logger.Debug("upload error", zap.Error(err))
		return nil, status.Error(codes.Internal, fmt.Sprintf("upload error: %s", err))
	}
	err = devInited.Connect(ctx)
	if err != nil {
		logger.Debug("upload error", zap.Error(err))
		return nil, status.Error(codes.Internal, fmt.Sprintf("upload error: %s", err))
	}
	uploadFiles := makeFilesUpload(req.GetFiles())
	err = devInited.Upload(uploadFiles)
	return &emptypb.Empty{}, err
}

func New(devAuthApp authApp, deviceFilePath string, opts ...Option) (*Server, error) {
	s := &Server{
		UnimplementedGnetcliServer: pb.UnimplementedGnetcliServer{},
		log:                        zap.NewNop(),
		deviceMapsMu:               sync.Mutex{},
		deviceMaps:                 nil,
		hostParams:                 map[string]hostParams{},
		hostParamsMu:               sync.Mutex{},
		devAuthApp:                 devAuthApp,
	}
	for _, opt := range opts {
		opt(s)
	}

	deviceMap, err := devconf.InitDeviceMapping(s.log, deviceFilePath)
	if err != nil {
		return nil, err
	} else {
		s.deviceMaps = deviceMap
	}
	return s, nil
}

func gnetcliTraceToTrace(tr gtrace.Trace) []*pb.CMDTraceItem {
	var traceRes []*pb.CMDTraceItem
	for _, v := range tr.List() {
		traceRes = append(traceRes, &pb.CMDTraceItem{Operation: pb.TraceOperation(v.GetOperation()) + 1, Data: v.GetData()})
	}
	return traceRes
}

func makeGnetcliCmd(cmd *pb.CMD) gcmd.Cmd {
	opts := make([]gcmd.CmdOption, 0, len(cmd.Qa))
	for _, qa := range cmd.Qa {
		opts = append(opts, gcmd.WithAddAnswers(gcmd.NewAnswer(qa.GetQuestion(), qa.GetAnswer())))
	}
	if cmdTimeout := cmd.GetCmdTimeout(); cmdTimeout != 0 {
		opts = append(opts, gcmd.WithCmdTimeout(time.Duration(cmdTimeout*float64(time.Second))))
	}
	if readTimeout := cmd.GetReadTimeout(); readTimeout != 0 {
		opts = append(opts, gcmd.WithReadTimeout(time.Duration(readTimeout*float64(time.Second))))
	}
	return gcmd.NewCmd(cmd.GetCmd(), opts...)
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

func BuildCreds(host, login, password string, enableAgent bool, sshConfig string, logger *zap.Logger) (credentials.Credentials, error) {
	if len(login) == 0 {
		newLogin := credentials.GetLogin()
		login = newLogin
	}

	if len(sshConfig) > 0 {
		sshConfigPassphrase := "" // TODO: pass it
		// here we read ssh config each call
		cred, err := BuildCredsFromSSHConfig(login, password, host, sshConfigPassphrase, "", logger)
		if err != nil {
			return nil, err
		}
		return cred, nil
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
	return creds, nil
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

func BuildCredsFromSSHConfig(login, password, host, sshConfigPassphrase, privateKeyPath string, logger *zap.Logger) (credentials.Credentials, error) {
	var privateKeys [][]byte
	if len(privateKeyPath) > 0 {
		key, err := os.ReadFile(privateKeyPath)
		if err != nil {
			return nil, err
		}
		privateKeys = [][]byte{key}
	} else {
		var err error
		privateKeys, err = credentials.GetPrivateKeysFromConfig(host)
		if err != nil {
			return nil, err
		}
	}
	if len(login) == 0 {
		configLogin := credentials.GetUsernameFromConfig(host)
		if len(configLogin) == 0 { // use current login
			newLogin := credentials.GetLogin()
			logger.Debug("Use system login", zap.String("configLogin", newLogin))
			login = newLogin
		} else {
			login = configLogin
			logger.Debug("Use login from config", zap.String("configLogin", configLogin))
		}
	} else {
		logger.Debug("Use login from input", zap.String("login", login))
	}
	agentSocket, err := credentials.GetAgentSocketFromConfig(host)
	if err != nil {
		return nil, err
	}

	opts := []credentials.CredentialsOption{
		credentials.WithUsername(login),
		credentials.WithLogger(logger),
		credentials.WithSSHAgentSocket(agentSocket),
	}
	if len(password) > 0 {
		opts = append(opts, credentials.WithPassword(credentials.Secret(password)))
	}
	if len(privateKeys) > 0 {
		opts = append(opts, credentials.WithPrivateKeys(privateKeys))
	}
	if len(sshConfigPassphrase) > 0 {
		opts = append(opts, credentials.WithPassphrase(credentials.Secret(sshConfigPassphrase)))
	}

	return credentials.NewSimpleCredentials(opts...), nil
}
