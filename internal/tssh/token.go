package tssh

import (
	"crypto/sha1"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode"

	"go.uber.org/zap"
)

func isHostValid(host string) bool {
	if strings.HasPrefix(host, "-") {
		return false
	}
	for _, ch := range host {
		if strings.ContainsRune("'`\"$\\;&<>|(){}", ch) {
			return false
		}
		if unicode.IsSpace(ch) || unicode.IsControl(ch) {
			return false
		}
	}
	return true
}

func isUserValid(user string) bool {
	if strings.HasPrefix(user, "-") {
		return false
	}
	if strings.ContainsAny(user, "'`\";&<>|(){}") {
		return false
	}
	// disallow '-' after whitespace
	if regexp.MustCompile(`\s-`).MatchString(user) {
		return false
	}
	// disallow \ in last position
	if strings.HasSuffix(user, "\\") {
		return false
	}
	return true
}

var getHostname = func() string {
	hostname, err := os.Hostname()
	if err != nil {
		logger := zap.Must(zap.NewProduction())
		logger.Error("get hostname failed", zap.Error(err))
		return ""
	}
	return hostname
}

type SshParam struct {
	host  string
	port  string
	user  string
	proxy []string
}

func NewSshParam(host, port, user string, proxy []string) *SshParam {
	return &SshParam{
		host:  host,
		port:  port,
		user:  user,
		proxy: proxy,
	}
}

func ExpandTokens(str string, param *SshParam, tokens string) (string, error) {
	if !strings.ContainsRune(str, '%') {
		return str, nil
	}
	var buf strings.Builder
	state := byte(0)
	for _, c := range str {
		if state == 0 {
			switch c {
			case '%':
				state = '%'
			default:
				buf.WriteRune(c)
			}
			continue
		}
		state = 0
		if !strings.ContainsRune(tokens, c) {
			return str, fmt.Errorf("token [%%%c] in [%s] is not supported", c, str)
		}
		switch c {
		case '%':
			buf.WriteRune('%')
		case 'h':
			if !isHostValid(param.host) {
				return str, fmt.Errorf("hostname contains invalid characters")
			}
			buf.WriteString(param.host)
		case 'p':
			buf.WriteString(param.port)
		case 'r':
			if !isUserValid(param.user) {
				return str, fmt.Errorf("remote username contains invalid characters")
			}
			buf.WriteString(param.user)
		case 'n':
			return "", fmt.Errorf("token [%%%c] in [%s] is not supported yet", c, str)
			// buf.WriteString(args.Destination)
		case 'l':
			buf.WriteString(getHostname())
		case 'L':
			hostname := getHostname()
			if idx := strings.IndexByte(hostname, '.'); idx >= 0 {
				hostname = hostname[:idx]
			}
			buf.WriteString(hostname)
		case 'j':
			if len(param.proxy) > 0 {
				buf.WriteString(param.proxy[len(param.proxy)-1])
			}
		case 'C':
			hashStr := fmt.Sprintf("%s%s%s%s", getHostname(), param.host, param.port, param.user)
			if len(param.proxy) > 0 && strings.ContainsRune(tokens, 'j') {
				hashStr += param.proxy[len(param.proxy)-1]
			}
			buf.WriteString(fmt.Sprintf("%x", sha1.Sum([]byte(hashStr))))
		case 'k':
			return "", fmt.Errorf("token [%%%c] in [%s] is not supported yet", c, str)
			// if hostKeyAlias := getOptionConfig(args, "HostKeyAlias"); hostKeyAlias != "" {
			// 	buf.WriteString(hostKeyAlias)
			// } else {
			// 	buf.WriteString(args.Destination)
			// }
		default:
			return str, fmt.Errorf("token [%%%c] in [%s] is not supported yet", c, str)
		}
	}
	if state != 0 {
		return str, fmt.Errorf("[%s] ends with %% is invalid", str)
	}
	return buf.String(), nil
}
