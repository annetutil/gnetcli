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
		[]byte("\r\n(M)<test-test>"),                  // mmi-mode
		[]byte("\r\n(M)[test-test]"),                  // mmi-mode system-view
		[]byte("\r\n(M)[5-1-1-GigabitEthernet1/0/1]"), // mmi-mode system-view
		[]byte("\r\n\x00<test>"),                      // banner terminated by a null byte
	}
	testutils.ExprTester(t, errorCases, promptExpression)
}
