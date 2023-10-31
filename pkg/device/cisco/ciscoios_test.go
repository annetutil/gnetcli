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
	}
	testutils.ExprTester(t, errorCases, promptExpression)
}

func TestQuestion(t *testing.T) {
	errorCases := [][]byte{
		[]byte("\r\nWarning: The current configuration will be written to the device. Continue? [Y/N]:"),
	}
	testutils.ExprTester(t, errorCases, questionExpression)
}
