package cisco

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
	}
	testutils.ExprTester(t, errorCases, errorExpression)
}

func TestPrompt(t *testing.T) {
	errorCases := [][]byte{
		[]byte("\r\ndcx1-j1#"),
		[]byte("\r\nhost-s2(config)#"),
		[]byte("\r\nhost-s2(config-if)#"),
		[]byte("\r\nhost-s2(config-if)#"),
		[]byte("\r\nhost-s2(config-archive-log-cfg)#"),
	}
	testutils.ExprTester(t, errorCases, promptExpression)
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

func TestQuestion(t *testing.T) {
	errorCases := [][]byte{
		[]byte("\r\nWarning: The current configuration will be written to the device. Continue? [Y/N]:"),
	}
	testutils.ExprTester(t, errorCases, questionExpression)
}
