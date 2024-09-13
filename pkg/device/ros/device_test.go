package ros

import (
	"testing"

	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/testutils"
)

func TestPrompt(t *testing.T) {
	cases := [][]byte{
		[]byte("\r\r\r\r[admin@mk-rb3011-test] >                                                       \r[admin@mk-rb3011-test] > "), // first prompt
	}
	testutils.ExprTester(
		t,
		cases,
		expr.NewExprMatcher(promptExpression, nil),
	)
}

func TestErrors(t *testing.T) {
	cases := [][]byte{
		[]byte("bad command name ttt (line 1 column 2)"),
		[]byte("syntax error (line 1 column 2)"),
		[]byte("[Safe mode released by another user]"),
		[]byte("expected end of command (line 1 column 5)"),
	}
	testutils.ExprTester(
		t,
		cases,
		expr.NewExprMatcher(errorExpression, nil),
	)
}

func TestQuestion(t *testing.T) {
	cases := [][]byte{
		[]byte("Reboot, yes? [y/N]:"),
		[]byte("\rnumbers: "),
	}
	testutils.ExprTester(
		t,
		cases,
		expr.NewExprMatcher(questionExpression, nil),
	)
}
