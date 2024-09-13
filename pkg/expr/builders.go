package expr

import "regexp"

type SimpleExprBuilderSource interface {
	FromPattern(pattern string) Expr
	FromPatternAndExclude(pattern string, exclude string) Expr
	FromRegex(regex *regexp.Regexp) Expr
	FromRegexAndExclude(regex *regexp.Regexp, excludeRegex *regexp.Regexp) Expr
}

type simpleExprBuilder struct {
	last  int
	first int
}

// NewSimpleExpr returns builder that creates a simple expr that will process data as is
func NewSimpleExpr() SimpleExprBuilderSource {
	return &simpleExprBuilder{
		last:  0,
		first: 0,
	}
}

// NewSimpleExprLast returns builder that creates a simple expr that will process only last n bytes of data
func NewSimpleExprLast(last int) SimpleExprBuilderSource {
	return &simpleExprBuilder{
		last:  last,
		first: 0,
	}
}

// NewSimpleExprLast200 is a wrapper around NewSimpleExprLast with last fixed to 200
func NewSimpleExprLast200() SimpleExprBuilderSource {
	return NewSimpleExprLast(200)
}

// NewSimpleExprLast20 is a wrapper around NewSimpleExprLast with last fixed to 20
func NewSimpleExprLast20() SimpleExprBuilderSource {
	return NewSimpleExprLast(20)
}

func NewSimpleExprFirst(first int) SimpleExprBuilderSource {
	return &simpleExprBuilder{
		last:  0,
		first: first,
	}
}

// NewSimpleExprFirst200 is a wrapper around NewSimpleExprFirst with first fixed to 200
func NewSimpleExprFirst200() SimpleExprBuilderSource {
	return NewSimpleExprFirst(200)
}

// FromPattern creates a simple expr matcher from compiling given pattern.
// Panics in case of compilation failure, use your own regex with FromRegex if passed pattern can be incorrect.
func (s *simpleExprBuilder) FromPattern(pattern string) Expr {
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
func (s *simpleExprBuilder) FromPatternAndExclude(pattern string, exclude string) Expr {
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
func (s *simpleExprBuilder) FromRegex(regex *regexp.Regexp) Expr {
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
func (s *simpleExprBuilder) FromRegexAndExclude(regex *regexp.Regexp, excludeRegex *regexp.Regexp) Expr {
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
