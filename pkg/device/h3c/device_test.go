package h3c

import (
	"testing"

	"github.com/annetutil/gnetcli/pkg/testutils"
)

func TestDeviceErrors(t *testing.T) {
	errorCases := [][]byte{
		[]byte(" % Error: Unrecognized command found at '^' position."),
		[]byte("                                   ^\r\n % Error:Too many parameters found at '^' position."),
		[]byte("\r\n % Unrecognized command found at '^' position."),
		[]byte("\r\n % Too many parameters found at '^' position."),
		[]byte("\r\n % Incomplete command found at '^' position."),
	}
	testutils.ExprTester(t, errorCases, errorExpression)
}

func TestDevicePrompt(t *testing.T) {
	errorCases := [][]byte{
		[]byte("\r\n<test>"),
		[]byte("\r\n(M)<test-test>"), // mmi-mode
	}
	testutils.ExprTester(t, errorCases, promptExpression)
}
