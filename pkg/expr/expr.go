/*
Package expr implements text matching.
*/
package expr

import (
	"regexp"
	"strings"
)

type MatchRes struct {
	Start     int
	End       int
	GroupDict map[string][]byte
	PatternNo int
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

type simpleExpr struct {
	exprs []*regexp.Regexp
	last  int
	first int
}

var _ Expr = (*simpleExpr)(nil)

func NewSimpleExpr(pattern string) Expr {
	return &simpleExpr{exprs: []*regexp.Regexp{regexp.MustCompile(pattern)}, last: 0, first: 0}
}

func NewSimpleExprLast200(pattern string) Expr {
	return NewSimpleExprLast(pattern, 200)
}

func NewSimpleExprFirst200(pattern string) Expr {
	return NewSimpleExprFirst(pattern, 200)
}

func NewSimpleExprLast20(pattern string) Expr {
	return NewSimpleExprLast(pattern, 20)
}

func NewSimpleExprLast(pattern string, last int) Expr {
	return &simpleExpr{exprs: []*regexp.Regexp{regexp.MustCompile(pattern)}, last: last, first: 0}
}

func NewSimpleExprFirst(pattern string, first int) Expr {
	return &simpleExpr{exprs: []*regexp.Regexp{regexp.MustCompile(pattern)}, last: 0, first: first}
}

func (m simpleExpr) Repr() string {
	resList := []string{}
	for _, expr := range m.exprs {
		resList = append(resList, expr.String())
	}
	return strings.Join(resList, ",")
}

func (m simpleExpr) String() string {
	return m.Repr()
}

func (m simpleExpr) Match(data []byte) (*MatchRes, bool) {
	var match []int
	var expr *regexp.Regexp
	var patterNo int
	checkData := data
	offset := 0
	if m.last > 0 && len(data) > m.last {
		offset = len(data) - m.last
		checkData = data[offset:]
	} else if m.first > 0 && len(data) > m.first {
		checkData = data[0:m.first]
	}

	for patterNo, expr = range m.exprs {
		if len(expr.String()) == 0 { // skip empty pattern
			continue
		}
		match = expr.FindStringSubmatchIndex(string(checkData))
		if len(match) != 0 {
			break
		}
	}
	if len(match) == 0 {
		return nil, false
	}
	paramsMap := make(map[string][]byte)
	for i, name := range expr.SubexpNames() {
		if i > 0 {
			if match[i*2] < 0 {
				continue
			}
			paramsMap[name] = data[offset+match[i*2] : offset+match[i*2+1]]
		}
	}

	return &MatchRes{Start: offset + match[0], End: offset + match[1], GroupDict: paramsMap, PatternNo: patterNo}, true
}

func NewSimpleExprListStr(patterns []string) Expr {
	exprs := make([]*regexp.Regexp, len(patterns))
	for i, pattern := range patterns {
		exprs[i] = regexp.MustCompile(pattern)
	}
	return &simpleExpr{exprs: exprs, last: 0, first: 0}
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
	for k, v := range m.exprsName {
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
		if mRes, ok := expr.Match(data); ok {
			mRes.PatternNo = i
			return mRes, true
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
