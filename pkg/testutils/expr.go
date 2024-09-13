/*
Package testutils provides functions to use in complex tests.
*/
package testutils

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/annetutil/gnetcli/pkg/expr"
)

func ExprTester(t *testing.T, cases [][]byte, expressions ...string) {
	var errorExpr expr.Expr

	if len(expressions) == 0 {

	} else if len(expressions) == 1 {
		errorExpr = expr.NewSimpleExpr().FromPattern(expressions[0])
	} else {
		var errorExprList []expr.Expr
		for _, expression := range expressions {
			errorExprList = append(errorExprList, expr.NewSimpleExpr().FromPattern(expression))
		}
		errorExpr = expr.NewSimpleExprList(errorExprList...)
	}

	for _, tc := range cases {
		t.Run("", func(t *testing.T) {
			res, ok := errorExpr.Match(tc)
			require.True(t, ok, fmt.Sprintf("regex: %q not matched\ndata: '%q'", errorExpr.Repr(), tc))
			require.NotNil(t, res)
		})
	}
}

type ExpressionPair struct {
	Pattern        string
	ExcludePattern string
}

func ExprExcludeTester(t *testing.T, cases [][]byte, expressions ...ExpressionPair) {
	var errorExpr expr.Expr

	if len(expressions) == 0 {

	} else if len(expressions) == 1 {
		errorExpr = expr.NewSimpleExpr().FromPatternAndExclude(
			expressions[0].Pattern,
			expressions[0].ExcludePattern,
		)
	} else {
		var errorExprList []expr.Expr
		for _, expression := range expressions {
			errorExprList = append(
				errorExprList,
				expr.NewSimpleExpr().FromPatternAndExclude(
					expression.Pattern,
					expression.ExcludePattern,
				))
		}
		errorExpr = expr.NewSimpleExprList(errorExprList...)
	}

	for _, tc := range cases {
		t.Run("", func(t *testing.T) {
			res, ok := errorExpr.Match(tc)
			require.True(t, ok, fmt.Sprintf("regex: %q not matched\ndata: '%q'", errorExpr.Repr(), tc))
			require.NotNil(t, res)
		})
	}
}

func ExprTesterFalse(t *testing.T, errorCases [][]byte, expression string) {
	errorExpr := expr.NewSimpleExpr().FromPattern(expression)
	for _, tc := range errorCases {
		t.Run("", func(t *testing.T) {
			res, ok := errorExpr.Match(tc)
			assert.False(t, ok, errorExpr.Repr())
			assert.Nil(t, res)
		})
	}
}
