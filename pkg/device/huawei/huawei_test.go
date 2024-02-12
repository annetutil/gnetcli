package huawei

import (
	"testing"

	"github.com/annetutil/gnetcli/pkg/testutils"
)

func TestHuaweiErrors(t *testing.T) {
	errorCases := [][]byte{
		[]byte("             ^\r\nError: Unrecognized command found at '^' position.\r\n"),
		[]byte("\r\nError: You do not have permission to run the command or the command is incomplete.\r\n"),
		[]byte("Error: Unrecognized command found at '^' position."),
		[]byte("Error: No permission to run the command."),
		[]byte("Error: You do not have permission to run the command or the command is incomplete."),
		[]byte("Error: Invalid file name log."),
		[]byte("              ^\r\nError[1]: Unrecognized command found at '^' position."),
		[]byte("              ^\r\nError[2]: Incomplete command found at '^' position."),
		[]byte("                                   ^\r\nError:Too many parameters found at '^' position."),
	}
	testutils.ExprTester(t, errorCases, errorExpression)
}

func TestHuaweiPrompt(t *testing.T) {
	errorCases := [][]byte{
		[]byte("\r\n<ce8850-test>"),
		[]byte("\r\n[~host-name]"),
		[]byte("\r\n[*host-name-aaa]"),
		[]byte("\r\n[~hostname-1-100GE11/0/25]"),
		[]byte("[*host-100GE1/1/1:1]"),
		[]byte("[~host-auto-mmm-100GE3/3/3.111]"),
	}
	testutils.ExprTester(t, errorCases, promptExpression)
}

func TestHuaweiNotPrompt(t *testing.T) {
	errorCases := [][]byte{
		[]byte("\r\n local-user username password irreversible-cipher ..cut..:SL<->"), // from config aaa section
	}
	testutils.ExprTesterFalse(t, errorCases, promptExpression)
}

func TestHuaweiQuestion(t *testing.T) {
	errorCases := [][]byte{
		[]byte("\r\nWarning: The current configuration will be written to the device. Continue? [Y/N]:"),
	}
	testutils.ExprTester(t, errorCases, questionExpression)
}
