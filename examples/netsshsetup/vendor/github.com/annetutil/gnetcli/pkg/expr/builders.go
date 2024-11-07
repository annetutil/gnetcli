package expr

import "regexp"

type SimpleExprBuilder struct {
	last  int
	first int
}

// NewSimpleExpr returns builder that creates a simple expr that will process data as is
func NewSimpleExpr() *SimpleExprBuilder {
	return &SimpleExprBuilder{
		last:  0,
		first: 0,
	}
}

// NewSimpleExprLast returns builder that creates a simple expr that will match only last n bytes of data
func NewSimpleExprLast(last int) *SimpleExprBuilder {
	return &SimpleExprBuilder{
		last:  last,
		first: 0,
	}
}

// NewSimpleExprLast200 is a wrapper around NewSimpleExprLast with last fixed to 200
func NewSimpleExprLast200() *SimpleExprBuilder {
	return NewSimpleExprLast(200)
}

// NewSimpleExprLast20 is a wrapper around NewSimpleExprLast with last fixed to 20
func NewSimpleExprLast20() *SimpleExprBuilder {
	return NewSimpleExprLast(20)
}

// NewSimpleExprLast returns builder that creates a simple expr that will match only first n bytes of data
func NewSimpleExprFirst(first int) *SimpleExprBuilder {
	return &SimpleExprBuilder{
		last:  0,
		first: first,
	}
}

// NewSimpleExprFirst200 is a wrapper around NewSimpleExprFirst with first fixed to 200
func NewSimpleExprFirst200() *SimpleExprBuilder {
	return NewSimpleExprFirst(200)
}

// FromPattern creates a simple expr matcher from compiling given pattern.
// Panics in case of compilation failure, use your own regex with FromRegex if passed pattern can be incorrect.
func (s *SimpleExprBuilder) FromPattern(pattern string) Expr {
	return &simpleExpr{
		exprs: []exprMatcher{
			{
				matchExpr:   regexp.MustCompile(pattern),
				excludeExpr: nil,
			},
		},
		last:  s.last,
		first: s.first,
	}
}

// FromPatternAndExclude creates a simple expr matcher from compiling given match and exclude patterns.
// It will only match data that is matched by regex and is not matched by exclude regex.
// Panics in case of compilation failure, use your own regex with FromRegexAndExclude if passed patterns can be incorrect.
func (s *SimpleExprBuilder) FromPatternAndExclude(pattern string, exclude string) Expr {
	return &simpleExpr{
		exprs: []exprMatcher{
			{
				matchExpr:   regexp.MustCompile(pattern),
				excludeExpr: regexp.MustCompile(exclude),
			},
		},
		last:  s.last,
		first: s.first,
	}
}

// FromRegex creates a simple expr matcher from given regex
func (s *SimpleExprBuilder) FromRegex(regex *regexp.Regexp) Expr {
	return &simpleExpr{
		exprs: []exprMatcher{
			{
				matchExpr:   regex,
				excludeExpr: nil,
			},
		},
		last:  s.last,
		first: s.first,
	}
}

// FromRegexAndExclude creates a simple expr matcher from passed regex and exclude.
// It will only match data that is matched by regex and is not matched by exclude regex.
func (s *SimpleExprBuilder) FromRegexAndExclude(regex *regexp.Regexp, excludeRegex *regexp.Regexp) Expr {
	return &simpleExpr{
		exprs: []exprMatcher{
			{
				matchExpr:   regex,
				excludeExpr: excludeRegex,
			},
		},
		last:  s.last,
		first: s.first,
	}
}
