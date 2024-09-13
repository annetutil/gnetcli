package devconf

import (
	"fmt"
	"regexp"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/device"
	"github.com/annetutil/gnetcli/pkg/device/cisco"
	"github.com/annetutil/gnetcli/pkg/device/genericcli"
	"github.com/annetutil/gnetcli/pkg/device/huawei"
	"github.com/annetutil/gnetcli/pkg/device/juniper"
	"github.com/annetutil/gnetcli/pkg/device/netconf"
	"github.com/annetutil/gnetcli/pkg/device/nxos"
	"github.com/annetutil/gnetcli/pkg/device/pc"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/streamer"
)

const (
	FeatureAutocmds        = "autocmds"
	FeatureSpacesAfterEcho = "spaces_after_echo"
)

type DevConf struct {
	Name               string        `yaml:"name"`
	PromptExpression   string        `yaml:"prompt_expression"`
	ErrorExpression    string        `yaml:"error_expression"`
	PagerExpression    string        `yaml:"pager_expression"`
	QuestionExpression string        `yaml:"question_expression"`
	Features           []interface{} `yaml:"features"`
	Tests              TestsConf     `yaml:"tests"`
}

type TestsConf struct {
	PromptExpressionVariants []string `yaml:"prompt_expression_variants"`
	ErrorExpressionVariants  []string `yaml:"error_expression_variants"`
	PagerExpressionVariants  []string `yaml:"pager_expression_variants"`
}

type DevConfs []DevConf

func NewConf() *Conf {
	return &Conf{}
}

type Conf struct {
	Devices DevConfs `yaml:"devices"`
}

func (m DevConfs) Make() (map[string]*genericcli.GenericCLI, error) {
	res := map[string]*genericcli.GenericCLI{}
	for _, v := range m {
		dev, err := v.Make()
		if err != nil {
			return nil, fmt.Errorf("dev %v error %w", v, err)
		}
		res[v.Name] = dev
	}

	return res, nil
}

func (m DevConf) Make() (*genericcli.GenericCLI, error) {
	opts := []genericcli.GenericCLIOption{
		genericcli.WithSFTPEnabled(),
	}
	errorExpr := m.ErrorExpression
	if len(errorExpr) > 0 {
		_, err := regexp.Compile(errorExpr)
		if err != nil {
			return nil, fmt.Errorf("error expression error %w", err)
		}
	} else {
		errorExpr = "$.^" // must not match anything
	}

	if len(m.PagerExpression) > 0 {
		_, err := regexp.Compile(m.PagerExpression)
		if err != nil {
			return nil, fmt.Errorf("pager expression error %w", err)
		}
		opts = append(opts, genericcli.WithPager(expr.NewSimpleExprLast200().FromPattern(m.PagerExpression)))
	}
	if len(m.QuestionExpression) > 0 {
		_, err := regexp.Compile(m.QuestionExpression)
		if err != nil {
			return nil, fmt.Errorf("pager question error %w", err)
		}
		opts = append(opts, genericcli.WithQuestion(expr.NewSimpleExprLast200().FromPattern(m.QuestionExpression)))
	}
	for _, feature := range m.Features {
		switch featureTyped := feature.(type) {
		case string:
			switch featureTyped {
			case FeatureSpacesAfterEcho:
				a := genericcli.WithEchoExprFn(func(c cmd.Cmd) expr.Expr {
					return expr.NewSimpleExpr().FromPattern(fmt.Sprintf(`%s *\r\n`, regexp.QuoteMeta(string(c.Value()))))
				})
				opts = append(opts, a)
			default:
				return nil, fmt.Errorf("unknown feature '%s'", feature)
			}
		case map[string]interface{}:
			if len(featureTyped) != 1 {
				return nil, fmt.Errorf("unxpected feature len %d", len(featureTyped))
			}
			mapFeature := getLastItem(featureTyped)
			switch mapFeature {
			case FeatureAutocmds:
				autoCommands, err := toStrSlice(featureTyped[FeatureAutocmds])
				if err != nil {
					return nil, err
				}
				var autoCommandCmd []cmd.Cmd
				for _, autoCmd := range autoCommands {
					autoCommandCmd = append(autoCommandCmd, cmd.NewCmd(autoCmd))
				}
				opts = append(opts, genericcli.WithAutoCommands(autoCommandCmd))
			}
		default:
			return nil, fmt.Errorf("unknown type %v", feature)
		}
	}
	cli := genericcli.MakeGenericCLI(
		expr.NewSimpleExprLast200().FromPattern(m.PromptExpression),
		expr.NewSimpleExprLast200().FromPattern(errorExpr),
		opts...,
	)
	return &cli, nil
}

func getLastItem(input map[string]interface{}) string {
	var lastVal string
	for item := range input {
		lastVal = item
	}
	return lastVal
}

func toStrSlice(input interface{}) ([]string, error) {
	inputTyped, ok := input.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unknown type")
	}
	res := []string{}
	for _, item := range inputTyped {
		newVal, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("wrong type %v", item)
		}
		res = append(res, newVal)
	}
	return res, nil
}

func GenericCLIDevToDev(cli *genericcli.GenericCLI, opts ...genericcli.GenericDeviceOption) func(connector streamer.Connector) device.Device {
	return func(connector streamer.Connector) device.Device {
		res := genericcli.MakeGenericDevice(*cli, connector, opts...)
		return &res
	}
}

func GenericCLIWrapper(cliFn func(connector streamer.Connector, opts ...genericcli.GenericDeviceOption) genericcli.GenericDevice, logger *zap.Logger) func(streamer.Connector) device.Device {
	return func(connector streamer.Connector) device.Device {
		r := cliFn(connector, genericcli.WithDevLogger(logger))
		return &r
	}
}

func InitDefaultDeviceMapping(logger *zap.Logger) map[string]func(streamer.Connector) device.Device {
	deviceMaps := map[string]func(streamer.Connector) device.Device{
		"juniper": GenericCLIWrapper(juniper.NewDevice, logger),
		"huawei":  GenericCLIWrapper(huawei.NewDevice, logger),
		"cisco":   GenericCLIWrapper(cisco.NewDevice, logger),
		"nxos":    GenericCLIWrapper(nxos.NewDevice, logger),
		"pc":      pc.NewDevice,
		"netconf": netconf.BindDeviceOpts(netconf.NewDevice, netconf.WithLogger(logger)),
	}
	return deviceMaps
}

func LoadYamlDeviceConfigs(content []byte) (map[string]*genericcli.GenericCLI, error) {
	conf := NewConf()
	err := yaml.Unmarshal(content, &conf)
	if err != nil {
		return nil, err
	}
	res, err := conf.Devices.Make()
	if err != nil {
		return nil, err
	}
	return res, nil
}
