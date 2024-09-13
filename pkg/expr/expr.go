/*
Package expr implements text matching.
*/
package expr

import (
	"fmt"
	"regexp"
	"strings"
)

type MatchRes struct {
	Start      int
	End        int
	GroupDict  map[string][]byte
	PatternNo  int
	Underlying *MatchRes // for result chaining
}

type Expr interface {
	Match(data []byte) (mRes *MatchRes, ok bool)
	Repr() string
}

type ExprList interface {
	Expr
	Add(name string, expr Expr)
	GetName(no int) string
	Delete(name string)
}

type NamedExpr struct {
	Name  string
	Exprs []Expr
}

type ExprMatcher struct {
	matchExpr   *regexp.Regexp
	excludeExpr *regexp.Regexp
}

// NewExprMatcher returns matcher that matches strings to given pattern
// If excludePattern is specified, strings matching it won't be matched
func NewExprMatcher(pattern string, excludePattern *string) ExprMatcher {
	res := ExprMatcher{
		matchExpr: regexp.MustCompile(pattern),
	}
	if excludePattern != nil {
		res.excludeExpr = regexp.MustCompile(*excludePattern)
	}
	return res
}

// NewExprMatcher returns matcher that matches strings to given expr
// If excludeExpr is specified, strings matching it won't be matched
func NewExprMatcherRegex(expr *regexp.Regexp, excludeExpr *regexp.Regexp) ExprMatcher {
	return ExprMatcher{
		matchExpr:   expr,
		excludeExpr: excludeExpr,
	}
}

type matchRes struct {
	start     int
	end       int
	groupDict map[string][]byte
}

// Match tries to match given data against underlying regexes
func (e *ExprMatcher) Match(data []byte) (*matchRes, bool) {
	if len(e.matchExpr.String()) == 0 {
		return nil, false
	}
	match := e.matchExpr.FindStringSubmatchIndex(string(data))
	if len(match) == 0 {
		return nil, false
	}
	if e.excludeExpr != nil && e.excludeExpr.Match(data) {
		return nil, false
	}
	paramsMap := make(map[string][]byte)
	for i, name := range e.matchExpr.SubexpNames() {
		if i > 0 {
			if match[i*2] < 0 {
				continue
			}
			paramsMap[name] = data[match[i*2]:match[i*2+1]]
		}
	}
	return &matchRes{
		start:     match[0],
		end:       match[1],
		groupDict: paramsMap,
	}, true
}

type simpleExpr struct {
	exprs []ExprMatcher
	last  int
	first int
}

type SimpleExprOption func(*simpleExpr)

func WithLast(last int) SimpleExprOption {
	return func(se *simpleExpr) {
		se.last = last
	}
}

func WithFirst(first int) SimpleExprOption {
	return func(se *simpleExpr) {
		se.first = first
	}
}

var _ Expr = (*simpleExpr)(nil)

func NewSimpleExprMatchers(matchers []ExprMatcher, opts ...SimpleExprOption) Expr {
	res := &simpleExpr{
		exprs: matchers,
		last:  0,
		first: 0,
	}
	for _, v := range opts {
		v(res)
	}
	return res
}

func NewSimpleExpr(pattern string, opts ...SimpleExprOption) Expr {
	res := &simpleExpr{
		exprs: []ExprMatcher{
			NewExprMatcher(pattern, nil),
		},
		last:  0,
		first: 0,
	}
	for _, v := range opts {
		v(res)
	}
	return res
}

func NewSimpleExprLast200(pattern string) Expr {
	return NewSimpleExpr(
		pattern,
		WithLast(200),
	)
}

func NewSimpleExprFirst200(pattern string) Expr {
	return NewSimpleExpr(
		pattern,
		WithFirst(200),
	)
}

func NewSimpleExprLast20(pattern string) Expr {
	return NewSimpleExpr(
		pattern,
		WithLast(20),
	)
}

func NewSimpleExprFromRegex(pattern *regexp.Regexp, opts ...SimpleExprOption) Expr {
	return NewSimpleExprMatchers(
		[]ExprMatcher{NewExprMatcherRegex(pattern, nil)},
		opts...,
	)
}

func NewSimpleExprFromRegexLast200(pattern *regexp.Regexp) Expr {
	return NewSimpleExprFromRegex(pattern, WithLast(200))
}

func NewSimpleExprFromRegexFirst200(pattern *regexp.Regexp) Expr {
	return NewSimpleExprFromRegex(pattern, WithFirst(200))
}

func NewSimpleExprFromRegexLast20(pattern *regexp.Regexp) Expr {
	return NewSimpleExprFromRegex(pattern, WithLast(20))
}

func (m simpleExpr) Repr() string {
	resList := []string{}
	for _, expr := range m.exprs {
		if expr.excludeExpr == nil {
			resList = append(
				resList,
				fmt.Sprintf(
					"{match: '%s'}",
					expr.matchExpr.String(),
				),
			)
			continue
		}
		resList = append(
			resList,
			fmt.Sprintf(
				"{match: '%s', exclude: '%s'}",
				expr.matchExpr.String(),
				expr.excludeExpr.String(),
			),
		)
	}
	return strings.Join(resList, ",")
}

func (m simpleExpr) String() string {
	return m.Repr()
}

func (m simpleExpr) Match(data []byte) (*MatchRes, bool) {
	checkData := data
	offset := 0
	if m.last > 0 && len(data) > m.last {
		offset = len(data) - m.last
		checkData = data[offset:]
	} else if m.first > 0 && len(data) > m.first {
		checkData = data[0:m.first]
	}

	for patterNo, expr := range m.exprs {
		res, ok := expr.Match(checkData)
		if ok {
			return &MatchRes{
				Start:      res.start + offset,
				End:        res.end + offset,
				GroupDict:  res.groupDict,
				PatternNo:  patterNo,
				Underlying: nil,
			}, true
		}
	}

	return nil, false
}

type SimpleExprList struct {
	exprs     []Expr
	exprsName map[int]string
}

var _ ExprList = (*SimpleExprList)(nil)

func NewSimpleExprListNamed(exprs map[string][]Expr) ExprList {
	res := SimpleExprList{exprs: []Expr{}, exprsName: map[int]string{}}
	for name, exprs := range exprs {
		for _, expr := range exprs {
			res.Add(name, expr)
		}
	}
	return &res
}

func NewSimpleExprListNamedOrdered(exprs []NamedExpr) ExprList {
	res := SimpleExprList{exprs: []Expr{}, exprsName: map[int]string{}}
	for _, namedExpr := range exprs {
		for _, expr := range namedExpr.Exprs {
			res.Add(namedExpr.Name, expr)
		}
	}
	return &res
}

func NewSimpleExprList(exprs ...Expr) ExprList {
	res := SimpleExprList{exprs: []Expr{}, exprsName: map[int]string{}}
	for _, expr := range exprs {
		res.Add("unnamed", expr)
	}
	return &res
}

func (m *SimpleExprList) Add(name string, expr Expr) {
	m.exprsName[len(m.exprs)] = name
	m.exprs = append(m.exprs, expr)
}

func (m *SimpleExprList) Delete(name string) {
	newList := SimpleExprList{exprs: []Expr{}, exprsName: map[int]string{}}
	// order of map iteration is not determined, so we keep order with this slice
	tmpExprs := make([]string, len(m.exprsName))
	for k, v := range m.exprsName {
		tmpExprs[k] = v
	}
	for k, v := range tmpExprs {
		if v != name {
			newList.Add(v, m.exprs[k])
		}
	}
	*m = newList
}

func (m *SimpleExprList) GetName(index int) string {
	return m.exprsName[index]
}

func (m SimpleExprList) Match(data []byte) (*MatchRes, bool) {
	for i, expr := range m.exprs {
		if expr == nil {
			continue
		}
		mRes, ok := expr.Match(data)
		if ok {
			res := &MatchRes{
				Start:      mRes.Start,
				End:        mRes.End,
				GroupDict:  mRes.GroupDict,
				PatternNo:  i,
				Underlying: mRes,
			}
			return res, true
		}
	}
	return nil, false
}

func (m SimpleExprList) Repr() string {
	resList := []string{}
	for _, expr := range m.exprs {
		if expr != nil {
			resList = append(resList, expr.Repr())
		}
	}
	return strings.Join(resList, ",")
}

func (m SimpleExprList) String() string {
	return m.Repr()
}
