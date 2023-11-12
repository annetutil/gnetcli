/*
Package testutils provides functions to use in complex tests.
*/
package testutils

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/annetutil/gnetcli/pkg/expr"
)

func ExprTester(t *testing.T, errorCases [][]byte, expressions ...string) {
	var errorExpr expr.Expr

	if len(expressions) == 0 {

	} else if len(expressions) == 1 {
		errorExpr = expr.NewSimpleExpr(expressions[0])
	} else {
		var errorExprList []expr.Expr
		for _, expression := range expressions {
			errorExprList = append(errorExprList, expr.NewSimpleExpr(expression))
		}
		errorExpr = expr.NewSimpleExprList(errorExprList...)
	}

	for _, tc := range errorCases {
		t.Run("", func(t *testing.T) {
			res, ok := errorExpr.Match(tc)
			assert.True(t, ok, fmt.Sprintf("regex: %s\ndata: %s", errorExpr.Repr(), tc))
			assert.NotNil(t, res)
		})
	}
}

func ExprTesterFalse(t *testing.T, errorCases [][]byte, expression string) {
	errorExpr := expr.NewSimpleExpr(expression)
	for _, tc := range errorCases {
		t.Run("", func(t *testing.T) {
			res, ok := errorExpr.Match(tc)
			assert.False(t, ok, errorExpr.Repr())
			assert.Nil(t, res)
		})
	}
}
