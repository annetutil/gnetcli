package ros

import (
	"testing"

	"github.com/annetutil/gnetcli/pkg/testutils"
)

func TestPrompt(t *testing.T) {
	cases := [][]byte{
		[]byte("\r\r\r\r[admin@mk-rb3011-test] >                                                       \r[admin@mk-rb3011-test] > "), // first prompt
	}
	testutils.ExprTester(t, cases, promptExpression)
}

func TestErrors(t *testing.T) {
	cases := [][]byte{
		[]byte("bad command name ttt (line 1 column 2)"),
		[]byte("syntax error (line 1 column 2)"),
		[]byte("[Safe mode released by another user]"),
	}
	testutils.ExprTester(t, cases, errorExpression)
}

func TestQuestion(t *testing.T) {
	cases := [][]byte{
		[]byte("Reboot, yes? [y/N]:"),
	}
	testutils.ExprTester(t, cases, questionExpression)
}
