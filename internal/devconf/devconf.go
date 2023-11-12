package devconf

import (
	"fmt"
	"regexp"

	"go.uber.org/zap"

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

type DevConf struct {
	Name             string `yaml:"name"`
	PromptExpression string `yaml:"prompt_expression"`
	ErrorExpression  string `yaml:"error_expression"`
	PagerExpression  string `yaml:"pager_expression"`
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
		opts = append(opts, genericcli.WithPager(expr.NewSimpleExprLast200(m.PagerExpression)))
	}

	cli := genericcli.MakeGenericCLI(
		expr.NewSimpleExprLast200(m.PromptExpression),
		expr.NewSimpleExprLast200(errorExpr),
		opts...,
	)
	return &cli, nil
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
