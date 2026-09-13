package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/annetutil/gnetcli/pkg/server/proto"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	reflectionpb "google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
	"google.golang.org/grpc/status"
)

// Run the real process entry point in the test binary (including under -race).
func TestServerProcess(t *testing.T) {
	if os.Getenv("GNETCLI_SERVER_TEST_PROCESS") != "1" {
		return
	}
	flag.CommandLine = flag.NewFlagSet("gnetcli_server", flag.ExitOnError)
	os.Args = []string{os.Args[0], "-conf-file", os.Getenv("GNETCLI_SERVER_TEST_CONFIG")}
	if value := os.Getenv("GNETCLI_SERVER_TEST_ARGS"); value != "" {
		var args []string
		if err := json.Unmarshal([]byte(value), &args); err != nil {
			panic(err)
		}
		os.Args = append([]string{os.Args[0]}, args...)
	}
	main()
	os.Exit(0)
}

type serverProcess struct {
	cmd                          *exec.Cmd
	done                         chan struct{}
	err                          error
	logPath                      string
	grpcAddr, httpAddr, unixAddr string
}

func (p *serverProcess) wait(t *testing.T) {
	t.Helper()
	select {
	case <-p.done:
		data, _ := os.ReadFile(p.logPath)
		require.NoError(t, p.err, string(data))
	case <-time.After(15 * time.Second):
		p.cmd.Process.Kill()
		<-p.done
		data, _ := os.ReadFile(p.logPath)
		t.Fatalf("server did not stop: %s", data)
	}
}
func startServerProcess(t *testing.T, config string, wantHTTP bool, args ...string) *serverProcess {
	t.Helper()
	dir := t.TempDir()
	conf := filepath.Join(dir, "server.yml")
	require.NoError(t, os.WriteFile(conf, []byte(config+"\nlogging: {json: true, level: info}\n"), 0600))
	logPath := filepath.Join(dir, "server.log")
	logfile, err := os.Create(logPath)
	require.NoError(t, err)
	process := &serverProcess{done: make(chan struct{}), logPath: logPath}
	process.cmd = exec.Command(os.Args[0], "-test.run=^TestServerProcess$")
	process.cmd.Env = append(os.Environ(), "GNETCLI_SERVER_TEST_PROCESS=1", "GNETCLI_SERVER_TEST_CONFIG="+conf)
	if len(args) > 0 {
		data, err := json.Marshal(args)
		require.NoError(t, err)
		process.cmd.Env = append(process.cmd.Env, "GNETCLI_SERVER_TEST_ARGS="+string(data))
	}
	process.cmd.Stdout = logfile
	process.cmd.Stderr = logfile
	require.NoError(t, process.cmd.Start())
	go func() { process.err = process.cmd.Wait(); logfile.Close(); close(process.done) }()
	t.Cleanup(func() {
		select {
		case <-process.done:
			return
		default:
		}
		_ = process.cmd.Process.Signal(os.Interrupt)
		process.wait(t)
	})
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(logPath)
		select {
		case <-process.done:
			t.Fatalf("server exited early: %s", data)
		default:
		}
		for _, line := range bytes.Split(data, []byte{'\n'}) {
			var event struct {
				Msg     string `json:"msg"`
				Address string `json:"address"`
				Path    string `json:"path"`
			}
			if json.Unmarshal(line, &event) != nil {
				// CLI-only mode uses the development logger, with JSON fields
				// after the message rather than one JSON object per line.
				start := bytes.IndexByte(line, '{')
				if start < 0 || json.Unmarshal(line[start:], &event) != nil {
					continue
				}
				for _, msg := range []string{"init tcp socket", "init http gateway socket", "init unix socket"} {
					if bytes.Contains(line[:start], []byte(msg)) {
						event.Msg = msg
						break
					}
				}
			}
			switch event.Msg {
			case "init tcp socket":
				process.grpcAddr = event.Address
			case "init http gateway socket":
				process.httpAddr = event.Address
			case "init unix socket":
				process.unixAddr = event.Path
			}
		}
		if (process.grpcAddr != "" || process.unixAddr != "") && (!wantHTTP || process.httpAddr != "") {
			return process
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("server startup timed out")
	return nil
}

func testTLS(t *testing.T) (string, string, credentials.TransportCredentials) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	dir := t.TempDir()
	certfile, keyfile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certfile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	require.NoError(t, os.WriteFile(keyfile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600))
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return certfile, keyfile, credentials.NewTLS(&tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12})
}

func TestSharedAndSeparateGateway(t *testing.T) {
	for _, tc := range []struct {
		name, listen, http string
		tls                bool
	}{
		{"shared", "127.0.0.1:0", "127.0.0.1:0", false},
		{"shared_flags", "127.0.0.1:0", "127.0.0.1:0", false},
		{"shared_short_port", "0", "127.0.0.1:0", false},
		{"wildcard", "0.0.0.0:0", "0.0.0.0:0", false},
		{"separate", "127.0.0.1:0", "localhost:0", false},
		{"shared_tls", "127.0.0.1:0", "127.0.0.1:0", true},
		{"separate_tls", "127.0.0.1:0", "localhost:0", true},
		{"grpc_only", "127.0.0.1:0", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := fmt.Sprintf("port: %q\nhttp_port: %q\nbasic_auth: 'test:secret'\n", tc.listen, tc.http)
			var creds credentials.TransportCredentials = insecure.NewCredentials()
			if tc.tls {
				certfile, keyfile, tlsCreds := testTLS(t)
				config += fmt.Sprintf("tls: true\ncert_file: %q\nkey_file: %q\n", certfile, keyfile)
				creds = tlsCreds
			}
			var args []string
			if tc.name == "shared_flags" {
				args = []string{"-port", tc.listen, "-http_port", tc.http, "-basic-auth", "test:secret"}
			}
			p := startServerProcess(t, config, tc.http != "", args...)
			if tc.http != "" && tc.http != "localhost:0" {
				require.Equal(t, p.grpcAddr, p.httpAddr)
			}
			if tc.http == "localhost:0" {
				require.NotEqual(t, p.grpcAddr, p.httpAddr)
			}
			endpoint := p.grpcAddr
			if tc.listen == "0.0.0.0:0" {
				_, port, err := net.SplitHostPort(endpoint)
				require.NoError(t, err)
				endpoint = net.JoinHostPort("127.0.0.1", port)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			conn, err := grpc.DialContext(ctx, endpoint, grpc.WithBlock(), grpc.WithTransportCredentials(creds))
			require.NoError(t, err)
			defer conn.Close()
			client := pb.NewGnetcliClient(conn)
			_, err = client.SetupHostParams(ctx, &pb.HostParams{Host: "grpc-device", Device: "huawei"})
			require.Equal(t, codes.Unauthenticated, status.Code(err))
			token := "Basic " + base64.StdEncoding.EncodeToString([]byte("test:secret"))
			authCtx := metadata.AppendToOutgoingContext(ctx, "authorization", token)
			_, err = client.SetupHostParams(authCtx, &pb.HostParams{Host: "grpc-device", Device: "huawei"})
			require.NoError(t, err)
			stream, err := reflectionpb.NewServerReflectionClient(conn).ServerReflectionInfo(authCtx)
			require.NoError(t, err)
			require.NoError(t, stream.Send(&reflectionpb.ServerReflectionRequest{MessageRequest: &reflectionpb.ServerReflectionRequest_ListServices{ListServices: ""}}))
			reply, err := stream.Recv()
			require.NoError(t, err)
			require.NotEmpty(t, reply.GetListServicesResponse().Service)
			if tc.http != "" {
				httpAddr := p.httpAddr
				if tc.listen == "0.0.0.0:0" {
					httpAddr = endpoint
				}
				transport := &http.Transport{Proxy: nil}
				defer transport.CloseIdleConnections()
				httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}
				for _, auth := range []string{"", "Basic wrong", token} {
					req, err := http.NewRequestWithContext(ctx, "POST", "http://"+httpAddr+"/api/v1/setup_host_params", strings.NewReader(`{"host":"http-device","device":"huawei"}`))
					require.NoError(t, err)
					req.Header.Set("Authorization", auth)
					req.Header.Set("Content-Type", "application/json")
					resp, err := httpClient.Do(req)
					require.NoError(t, err)
					body, err := io.ReadAll(resp.Body)
					resp.Body.Close()
					require.NoError(t, err)
					want := http.StatusUnauthorized
					if auth == token {
						want = http.StatusOK
					}
					require.Equal(t, want, resp.StatusCode, string(body))
				}
			}
			// A slow classifier must not block shutdown. An established stream
			// must remain alive until it is drained, not be closed by the mux.
			idle, err := net.Dial("tcp", endpoint)
			require.NoError(t, err)
			defer idle.Close()
			require.NoError(t, p.cmd.Process.Signal(os.Interrupt))
			select {
			case <-p.done:
				t.Fatal("server exited before the active stream drained")
			case <-time.After(100 * time.Millisecond):
			}
			require.NoError(t, stream.CloseSend())
			_, err = stream.Recv()
			require.ErrorIs(t, err, io.EOF)
			p.wait(t)
		})
	}
}

func TestUnixOnlyStillWorks(t *testing.T) {
	// Unix socket paths have a small OS limit; use a short temporary directory.
	dir, err := os.MkdirTemp("", "gnet-unix-")
	require.NoError(t, err)
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "s")
	p := startServerProcess(t, fmt.Sprintf("disable_tcp: true\nunix_socket: %q\nbasic_auth: 'test:secret'\n", socket), false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, "unix:"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	require.NoError(t, err)
	defer conn.Close()
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("test:secret")))
	_, err = pb.NewGnetcliClient(conn).SetupHostParams(ctx, &pb.HostParams{Host: "unix-device", Device: "huawei"})
	require.NoError(t, err)
	require.NoError(t, p.cmd.Process.Signal(os.Interrupt))
	p.wait(t)
}
