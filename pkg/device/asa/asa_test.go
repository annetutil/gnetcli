package ciscoasa

import (
	"testing"

	"github.com/annetutil/gnetcli/pkg/testutils"
)

func TestErrors(t *testing.T) {

	errorCases := [][]byte{
		[]byte("              ^\r\n% Invalid input detected at '^' marker.\r\n\r\n"),
		[]byte("% Bad IP address or host name% Unknown command or computer name, or unable to find computer address"),
		[]byte("% Ambiguous command:  \"dis clock\""),
		[]byte("                  ^\n% Ambiguous command at '^' marker."),
		[]byte("% Specify remote-as or peer-group remote AS first"),
		[]byte("ERROR: % Invalid input detected at '^' marker."),
		[]byte("ERROR: % Unrecognized command"),
		[]byte("% Permission denied for the role"),
		[]byte("\r% Permission denied for the role"),
		[]byte("% This command is not authorized"),
		[]byte("\r% This command is not authorized"),
		[]byte("% Failed to commit one or more configuration commands"),
		[]byte("\r% Failed to commit the configuration"),
		[]byte("% Bad OID value"),
		[]byte("\n% Bad IP address"),
		[]byte("% Invalid input"),
		[]byte("Permission denied: Access denied [Errno 13] Permission denied"),
		[]byte("     ^\n% Ambiguous command at '^' marker."),
		[]byte("     ^\nInvalid command at '^' marker."),
		[]byte("% Specify interface name first"),
		[]byte("                        ^\nERROR: % Invalid input detected at '^' marker."),
	}
	testutils.ExprTester(t, errorCases, errorExpression)
}

func TestPromptCiscoASA(t *testing.T) {
	testCases := [][]byte{
		[]byte("\r\ncisco-asa-fw-01#"),
		[]byte("\r\ncisco-asa-fw-01(config)#"),
		[]byte("\r\nasa-fw.example.com#"),
		[]byte("\r\nASA-5520(config)#"),
		[]byte("\r\nfirewall-asa(config-if)#"),
		[]byte("\r\ncisco-asa-prod(config-webvpn)#"),
		[]byte("\r\nmy-asa-device>"), // User mode
		[]byte("\r\n\rcisco-asa-fw-01# "),
	}
	testutils.ExprTester(t, testCases, promptExpression)
}

func TestLogin(t *testing.T) {
	errorCases := [][]byte{
		[]byte("\r\n\r\nUser Access Verification\r\n\r\nUsername: "),
	}
	testutils.ExprTester(t, errorCases, loginExpression)
}

func TestPassword(t *testing.T) {
	errorCases := [][]byte{
		[]byte("\r\nPassword: "),
	}
	testutils.ExprTester(t, errorCases, passwordExpression)
}

func TestErrorPassword(t *testing.T) {
	cases := [][]byte{
		[]byte("\r\n% Authentication failed\r\n\r\n"),
	}
	testutils.ExprTester(t, cases, passwordErrorExpression)
}

func TestQuestion(t *testing.T) {
	errorCases := [][]byte{
		[]byte("\r\nWarning: The current configuration will be written to the device. Continue? [Y/N]:"),
	}
	testutils.ExprTester(t, errorCases, questionExpression)
}
