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
	extCases := make([]ExprCase, 0, len(cases))
	for _, tCase := range cases {
		extCases = append(extCases, ExprCase{Input: tCase, BeforeIgnore: true})
	}
	ExprTesterExtended(t, extCases, expressions...)
}

type ExprCase struct {
	Input        []byte
	Before       []byte
	BeforeIgnore bool
}

func ExprTesterExtended(t *testing.T, cases []ExprCase, expressions ...string) {
	var testExpr expr.Expr

	if len(expressions) == 0 {

	} else if len(expressions) == 1 {
		testExpr = expr.NewSimpleExpr().FromPattern(expressions[0])
	} else {
		var errorExprList []expr.Expr
		for _, expression := range expressions {
			errorExprList = append(errorExprList, expr.NewSimpleExpr().FromPattern(expression))
		}
		testExpr = expr.NewSimpleExprList(errorExprList...)
	}

	for _, tc := range cases {
		t.Run("", func(t *testing.T) {
			res, ok := testExpr.Match(tc.Input)
			require.True(t, ok, fmt.Sprintf("regex: %s not matched\ndata: %v", testExpr.Repr(), tc))
			require.NotNil(t, res)
			if !tc.BeforeIgnore {
				before := tc.Input[:res.Start]
				require.Equal(t, tc.Before, before)
			}
		})
	}
}

type ExpressionPair struct {
	Pattern        string
	ExcludePattern string
}

func ExprTesterWithExclude(t *testing.T, cases [][]byte, expressions ...ExpressionPair) {
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
func ExprTesterFalseWithExclude(t *testing.T, errorCases [][]byte, expression ExpressionPair) {
	errorExpr := expr.NewSimpleExpr().FromPatternAndExclude(expression.Pattern, expression.ExcludePattern)
	for _, tc := range errorCases {
		t.Run("", func(t *testing.T) {
			res, ok := errorExpr.Match(tc)
			assert.False(t, ok, errorExpr.Repr())
			assert.Nil(t, res)
		})
	}
}
