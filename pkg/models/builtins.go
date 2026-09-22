package models

import (
	"fmt"
	"regexp"
	"time"
	_ "time/tzdata" // Parsing does not depend on the host's zoneinfo installation.

	starjson "go.starlark.net/lib/json"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

func standardModule(name string) (starlark.StringDict, bool) {
	switch name {
	case "json.star":
		return starlark.StringDict{"json": starjson.Module}, true
	case "re.star":
		return starlark.StringDict{"re": &starlarkstruct.Module{Name: "re", Members: starlark.StringDict{
			"search": starlark.NewBuiltin("re.search", regexSearch),
		}}}, true
	case "time.star":
		return starlark.StringDict{"time": &starlarkstruct.Module{Name: "time", Members: starlark.StringDict{
			"parse_ns": starlark.NewBuiltin("time.parse_ns", parseTime),
		}}}, true
	}
	return nil, false
}

// search returns None or [whole_match, group_1, ...], using Go/RE2 syntax.
func regexSearch(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var pattern, text string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "pattern", &pattern, "text", &text); err != nil {
		return nil, err
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	match := re.FindStringSubmatch(text)
	if match == nil {
		return starlark.None, nil
	}
	values := make([]starlark.Value, len(match))
	for i, v := range match {
		values[i] = starlark.String(v)
	}
	return starlark.NewList(values), nil
}

// parse_ns uses a Go time layout and an explicit IANA location (UTC by default).
func parseTime(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value, layout string
	location := "UTC"
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "value", &value, "layout", &layout, "location?", &location); err != nil {
		return nil, err
	}
	loc, err := time.LoadLocation(location)
	if err != nil {
		return nil, err
	}
	parsed, err := time.ParseInLocation(layout, value, loc)
	if err != nil {
		return nil, err
	}
	zone, offset := parsed.Zone()
	if offset == 0 && zone != "" && zone != "UTC" && zone != "GMT" {
		actual, _ := parsed.In(loc).Zone()
		if zone != actual {
			return nil, fmt.Errorf("unknown timezone %q", zone)
		}
	}
	ns := parsed.UnixNano()
	if ns < 0 || !time.Unix(0, ns).Equal(parsed) {
		return nil, fmt.Errorf("timestamp outside nonnegative int64 nanosecond range")
	}
	return starlark.MakeInt64(ns), nil
}
