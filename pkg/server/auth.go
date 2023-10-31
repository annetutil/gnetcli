package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	grpcmiddleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/annetutil/gnetcli/pkg/credentials"
)

var ErrUnauthorized = errors.New("unauthorized")

type Auth struct {
	login    string
	password credentials.Secret
	log      *zap.Logger
}

type ctxKey string

const usernameField ctxKey = "username"

func NewAuth(logger *zap.Logger, login string, password credentials.Secret) *Auth {
	return &Auth{
		login:    login,
		password: password,
		log:      logger,
	}
}

func NewAuthInsecure(logger *zap.Logger) *Auth {
	return &Auth{
		login:    "",
		password: "",
		log:      logger,
	}
}

func (m *Auth) AuthenticateUnary(ctx context.Context, req interface{}, servInfo *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	newCtx, err := m.authenticate(ctx)
	if err != nil {
		st := status.New(codes.Unauthenticated, "unauthenticated")
		return nil, st.Err()
	}
	return handler(newCtx, req)
}

func (m *Auth) AuthenticateStream(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	ctx := ss.Context()
	newCtx, err := m.authenticate(ctx)
	if err != nil {
		st := status.New(codes.Unauthenticated, "unauthenticated")
		return st.Err()
	}
	return handler(srv, &grpcmiddleware.WrappedServerStream{ServerStream: ss, WrappedContext: newCtx})
}

func (m *Auth) authenticate(ctx context.Context) (context.Context, error) {
	m.log.Debug("authenticate")
	authRes, err := m.checkToken(ctx)
	if err != nil {
		m.log.Debug("authentication error")
		return nil, err
	}
	if authRes == nil {
		m.log.Error("empty auth")
		return nil, err
	}

	newCtx := setAuthContext(ctx, *authRes)
	m.log.Debug("authenticated")
	return newCtx, nil
}

func (m *Auth) checkToken(ctx context.Context) (*authInfo, error) {
	if len(m.login) == 0 && len(m.password) == 0 {
		return newAuthInfo(""), nil
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.New("missing metadata")
	}

	// by authorization header
	authorizationHeaderList := md.Get("authorization")
	authorizationHeader := ""
	if len(authorizationHeaderList) > 0 {
		authorizationHeader = authorizationHeaderList[0]
	}
	_, basicUser, basicPass, _, err := extractAuthTokens(authorizationHeader)
	if err != nil {
		return nil, errors.New("unable to parse auth")
	}
	if m.login == basicUser && m.password.Value() == basicPass {
		return newAuthInfo(basicUser), nil
	}
	return nil, ErrUnauthorized
}

func extractAuthTokens(authorizationHeader string) (bearer, basicUser, basicPass, oauth string, err error) {
	authorizationHeaderVals := strings.Split(authorizationHeader, " ")
	if len(authorizationHeaderVals) != 2 {
		return bearer, basicUser, basicPass, oauth, fmt.Errorf("wrong auth header")
	}
	authType := authorizationHeaderVals[0]
	authVal := authorizationHeaderVals[1]
	switch strings.ToLower(authType) {
	case "bearer": // for future usage
		bearer = authVal
	case "basic":
		decodedStr, err := base64.StdEncoding.DecodeString(authVal)
		if err != nil {
			return bearer, basicUser, basicPass, oauth, fmt.Errorf("b64 decode error %w", err)
		}
		pair := strings.SplitN(string(decodedStr), ":", 2)
		if len(pair) != 2 {
			return bearer, basicUser, basicPass, oauth, fmt.Errorf("split error %s", string(decodedStr))
		}
		basicUser = pair[0]
		basicPass = pair[1]
	case "oauth": // for future usage
		oauth = authVal
	default:
		return bearer, basicUser, basicPass, oauth, fmt.Errorf("unknown error type %s", authType)
	}
	return bearer, basicUser, basicPass, oauth, nil
}

type authInfo struct {
	user string
}

func newAuthInfo(user string) *authInfo {
	return &authInfo{user: user}
}

func setAuthContext(ctx context.Context, auth authInfo) context.Context {
	newCtx := context.WithValue(ctx, usernameField, auth)
	return newCtx
}
