package emulator

import (
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ArgumentSpec customizes hints and constraints for named typed arguments.
// Hint is display-only; word lengths count code points, numeric bounds are uint32.
// The terminal input editor remains ASCII-only.
type ArgumentSpec struct {
	Enum      []string `yaml:"enum"`
	MinValue  *uint32  `yaml:"minValue"`
	MaxValue  *uint32  `yaml:"maxValue"`
	Hint      string   `yaml:"hint"`
	MinLength int      `yaml:"minLength"`
	MaxLength int      `yaml:"maxLength"`
}

func (p *Profile) registerArguments(mode string, pat pattern, specs map[string]ArgumentSpec) error {
	for name, spec := range specs {
		if len(spec.Enum) == 0 {
			spec.Enum = nil
		}
		index := -1
		for i, token := range pat.tokens {
			if token.name == name {
				index = i
				break
			}
		}
		if index < 0 {
			return fmt.Errorf("command %s: argument specification %q must refer to a word argument or supported typed argument", pat.id, name)
		}
		kind := pat.tokens[index].kind
		if (spec.MinLength != 0 || spec.MaxLength != 0 || len(spec.Enum) > 0) && kind != "word" {
			return fmt.Errorf("length/enum constraints require a word argument")
		}
		if (spec.MinValue != nil || spec.MaxValue != nil) && kind != "uint" {
			return fmt.Errorf("numeric bounds require a uint argument")
		}
		if spec.MinValue != nil && spec.MaxValue != nil && *spec.MinValue > *spec.MaxValue {
			return fmt.Errorf("invalid numeric bounds")
		}
		if len(spec.Enum) > 64 {
			return fmt.Errorf("enum has too many values")
		}
		seen := map[string]bool{}
		for _, value := range spec.Enum {
			if value == "" || len(value) > 256 || !spec.acceptsLength(value) || seen[value] {
				return fmt.Errorf("invalid or duplicate enum value")
			}
			for _, b := range []byte(value) {
				if b < 33 || b > 126 {
					return fmt.Errorf("enum values must be printable ASCII words")
				}
			}
			seen[value] = true
		}
		if spec.MinLength < 0 || spec.MaxLength < 0 || (spec.MaxLength > 0 && spec.MinLength > spec.MaxLength) {
			return fmt.Errorf("command %s: invalid argument length bounds for %q", pat.id, name)
		}
		if len(spec.Hint) > 256 || spec.Hint == "<cr>" || strings.ContainsFunc(spec.Hint, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
			return fmt.Errorf("command %s: argument hint must be at most 256 bytes without whitespace/control characters and cannot be <cr>", pat.id)
		}
		if p.arguments == nil {
			p.arguments = map[string]map[string]ArgumentSpec{}
		}
		if p.arguments[mode] == nil {
			p.arguments[mode] = map[string]ArgumentSpec{}
		}
		path := helpPath(pat, index)
		if old, exists := p.arguments[mode][path]; exists && !reflect.DeepEqual(old, spec) {
			return fmt.Errorf("conflicting argument specification for %q in mode %q", path, mode)
		}
		p.arguments[mode][path] = spec
	}
	return nil
}

func (p *Profile) argumentSpec(mode string, pat pattern, index int) ArgumentSpec {
	return p.arguments[mode][helpPath(pat, index)]
}

func (a ArgumentSpec) acceptsLength(value string) bool {
	length := utf8.RuneCountInString(value)
	return length >= a.MinLength && (a.MaxLength == 0 || length <= a.MaxLength)
}

func (a ArgumentSpec) acceptsValue(kind, value string) bool {
	if !a.acceptsLength(value) {
		return false
	}
	if len(a.Enum) > 0 && !slices.Contains(a.Enum, value) {
		return false
	}
	switch kind {
	case "uint":
		number, err := strconv.ParseUint(value, 10, 32)
		return err == nil && (a.MinValue == nil || number >= uint64(*a.MinValue)) && (a.MaxValue == nil || number <= uint64(*a.MaxValue))
	case "ip", "ipv4", "ipv6":
		address, err := netip.ParseAddr(value)
		return err == nil && address.Zone() == "" && (kind == "ip" || kind == "ipv4" && address.Is4() || kind == "ipv6" && address.Is6())
	case "mac":
		address, err := net.ParseMAC(value)
		return err == nil && len(address) == 6
	default:
		return true
	}
}
