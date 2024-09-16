package expr

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExpr(t *testing.T) {
	cases := []struct {
		name  string
		input []byte
		expr  Expr
		match bool
	}{
		{
			name:  "Simple expr match",
			input: []byte("\r\nAre you sure?\n"),
			expr:  NewSimpleExpr().FromPattern("Are you sure?"),
			match: true,
		},
		{
			name:  "Simple expr exclude",
			input: []byte("\r\nAre you sure?\n"),
			expr:  NewSimpleExpr().FromPatternAndExclude("Are you sure?", "\r\n"),
			match: false,
		},
		{
			name:  "Simple expr no exclude",
			input: []byte("\r\nAre you sure?\n"),
			expr:  NewSimpleExpr().FromPatternAndExclude("Are you sure?", "\t"),
			match: true,
		},
	}
	for _, v := range cases {
		_, match := v.expr.Match(v.input)
		assert.Equal(t, v.match, match, v.name)
	}
}

func TestExprList(t *testing.T) {
	cases := []struct {
		name  string
		input []byte
		expr  ExprList
		match bool
	}{
		{
			name:  "List matches",
			input: []byte("\r\nAre you sure?\n"),
			expr: NewSimpleExprList(
				NewSimpleExpr().FromPattern("Are you sure?"),
			),
			match: true,
		},
		{
			name:  "Last list element matches",
			input: []byte("\r\nAre you sure?\n"),
			expr: NewSimpleExprList(
				NewSimpleExpr().FromPatternAndExclude("Are you sure?", "\r\n"),
				NewSimpleExpr().FromPatternAndExclude("Are you sure?", "\t"),
			),
			match: true,
		},
		{
			name:  "No matches",
			input: []byte("\r\nAre you sure?\n"),
			expr: NewSimpleExprList(
				NewSimpleExpr().FromPatternAndExclude("Are you sure?", "\r\n"),
			),
			match: false,
		},
	}
	for _, v := range cases {
		_, match := v.expr.Match(v.input)
		assert.Equal(t, v.match, match, v.name)
	}
}
