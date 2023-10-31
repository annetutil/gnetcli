package netconf

import (
	"testing"

	"github.com/annetutil/gnetcli/pkg/device"
	"github.com/annetutil/gnetcli/pkg/streamer"
	m "github.com/annetutil/gnetcli/pkg/testutils/mock"
)

var (
	everyDayHuaweiHello = []m.Action{
		m.Send("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n  " +
			"<capabilities>\n    " +
			"<capability>urn:ietf:params:netconf:base:1.0</capability>\n    " +
			"<capability>urn:ietf:params:netconf:base:1.1</capability>\n    " +
			"<capability>urn:ietf:params:netconf:capability:schema-sets:1.0?list=huawei-yang@2.0.0</capability>\n    " +
			"<capability>urn:ietf:params:netconf:capability:writable-running:1.0</capability>\n    " +
			"<capability>urn:ietf:params:netconf:capability:candidate:1.0</capability>\n    " +
			"<capability>urn:ietf:params:netconf:capability:confirmed-commit:1.0</capability>\n    " +
			"<capability>urn:ietf:params:netconf:capability:confirmed-commit:1.1</capability>\n    " +
			"<capability>urn:ietf:params:netconf:capability:with-defaults:1.0?basic-mode=report-all&amp;also-supported=report-all-tagged,trim</capability>\n    " +
			"<capability>http://www.huawei.com/netconf/capability/discard-commit/1.0</capability>\n    " +
			"<capability>urn:ietf:params:netconf:capability:xpath:1.0</capability>\n    " +
			"<capability>urn:ietf:params:netconf:capability:startup:1.0</capability>\n    " +
			"<capability>urn:ietf:params:netconf:capability:rollback-on-error:1.0</capability>\n    " +
			"<capability>http://www.huawei.com/netconf/capability/sync/1.3</capability>\n    " +
			"<capability>http://www.huawei.com/netconf/capability/sync/1.2</capability>\n    " +
			"<capability>http://www.huawei.com/netconf/capability/sync/1.1</capability>\n    " +
			"<capability>http://www.huawei.com/netconf/capability/sync/1.0</capability>\n    " +
			"<capability>http://www.huawei.com/netconf/capability/exchange/1.0</capability>\n    " +
			"<capability>http://www.huawei.com/netconf/capability/exchange/1.2</capability>\n    " +
			"<capability>http://www.huawei.com/netconf/capability/active/1.0</capability>\n    " +
			"<capability>urn:ietf:params:netconf:capability:validate:1.0</capability>\n    " +
			"<capability>urn:ietf:params:netconf:capability:validate:1.1</capability>\n    " +
			"<capability>http://www.huawei.com/netconf/capability/action/1.0</capability>\n    " +
			"<capability>http://www.huawei.com/netconf/capability/execute-cli/1.0</capability>\n    " +
			"<capability>http://www.huawei.com/netconf/capability/update/1.0</capability>\n    " +
			"<capability>http://www.huawei.com/netconf/capability/commit-description/1.0</capability>\n    " +
			"<capability>urn:ietf:params:netconf:capability:url:1.0?scheme=file,ftp,sftp,http,https</capability>\n    " +
			"<capability>http://www.huawei.com/netconf/capability/schema/1.0</capability>\n    " +
			"<capability>urn:ietf:params:netconf:capability:notification:1.0</capability>\n    " +
			"<capability>urn:ietf:params:netconf:capability:interleave:1.0</capability>\n    " +
			"<capability>urn:ietf:params:netconf:capability:notification:2.0</capability>\n    " +
			"<capability>urn:ietf:params:netconf:capability:yang-library:1.0?revision=2016-06-21&amp;module-set-id=1489272061</capability>\n    " +
			"<capability>http://openconfig.net/yang/acl?module=openconfig-acl&amp;revision=2017-05-26&amp;deviations=huawei-openconfig-acl-deviations-CE6866</capability>\n    " +
			"<capability>http://openconfig.net/yang/alarms/types?module=openconfig-alarm-types&amp;revision=2018-01-16</capability>\n    " +
			"<capability>http://openconfig.net/yang/header-fields?module=openconfig-packet-match&amp;revision=2017-12-15</capability>\n    " +
			"<capability>http://openconfig.net/yang/interfaces?module=openconfig-interfaces&amp;revision=2018-01-05&amp;deviations=huawei-openconfig-interfaces-deviations-CE6866</capability>\n    " +
			"<capability>http://openconfig.net/yang/interfaces/aggregate?module=openconfig-if-aggregate&amp;revision=2020-05-01&amp;deviations=huawei-openconfig-if-aggregate-deviations-CE6866</capability>\n    " +
			"<capability>http://openconfig.net/yang/interfaces/ethernet?module=openconfig-if-ethernet&amp;revision=2020-05-06&amp;deviations=huawei-openconfig-if-ethernet-deviations-CE6866</capability>\n    " +
			"<capability>http://openconfig.net/yang/interfaces/ip?module=openconfig-if-ip&amp;revision=2018-01-05&amp;deviations=huawei-openconfig-if-ip-deviations-CE6866</capability>\n    " +
			"<capability>http://openconfig.net/yang/lacp?module=openconfig-lacp&amp;revision=2017-05-05&amp;deviations=huawei-openconfig-lacp-deviations-CE6866</capability>\n    " +
			"<capability>http://openconfig.net/yang/lldp?module=openconfig-lldp&amp;revision=2016-05-16&amp;deviations=huawei-openconfig-lldp-deviations-CE6866</capability>\n    " +
			"<capability>http://openconfig.net/yang/lldp/types?module=openconfig-lldp-types&amp;revision=2016-05-16</capability>\n    " +
			"<capability>http://openconfig.net/yang/openconfig-ext?module=openconfig-extensions&amp;revision=2018-10-17</capability>\n    " +
			"<capability>http://openconfig.net/yang/openconfig-if-types?module=openconfig-if-types&amp;revision=2018-01-05</capability>\n    " +
			"<capability>http://openconfig.net/yang/openconfig-types?module=openconfig-types&amp;revision=2019-04-16</capability>\n    " +
			"<capability>http://openconfig.net/yang/ospf-types?module=openconfig-ospf-types&amp;revision=2018-06-05</capability>\n    " +
			"<capability>http://openconfig.net/yang/packet-match-types?module=openconfig-packet-match-types&amp;revision=2018-09-14</capability>\n    " +
			"<capability>http://openconfig.net/yang/platform?module=openconfig-platform&amp;revision=2018-01-30&amp;deviations=huawei-openconfig-platform-deviations-CE6866</capability>\n    " +
			"<capability>http://openconfig.net/yang/platform-types?module=openconfig-platform-types&amp;revision=2018-05-05</capability>\n    " +
			"<capability>http://openconfig.net/yang/platform/fan?module=openconfig-platform-fan&amp;revision=2018-01-18</capability>\n    " +
			"<capability>http://openconfig.net/yang/platform/psu?module=openconfig-platform-psu&amp;revision=2018-01-16&amp;deviations=huawei-openconfig-platform-psu-deviations-CE6866</capability>\n    " +
			"<capability>http://openconfig.net/yang/platform/transceiver?module=openconfig-platform-transceiver&amp;revision=2018-01-22&amp;deviations=huawei-openconfig-platform-transceiver-deviations-CE6866</capability>\n    " +
			"<capability>http://openconfig.net/yang/qos?module=openconfig-qos&amp;revision=2016-12-16</capability>\n    " +
			"<capability>http://openconfig.net/yang/relay-agent?module=openconfig-relay-agent&amp;revision=2018-11-21&amp;deviations=openconfig-relay-agent-deviations-CE6866</capability>\n    " +
			"<capability>http://openconfig.net/yang/relay-agent-deviations-CE6866?module=openconfig-relay-agent-deviations-CE6866&amp;revision=2020-05-27</capability>\n    " +
			"<capability>http://openconfig.net/yang/telemetry?module=openconfig-telemetry&amp;revision=2017-08-24&amp;deviations=huawei-openconfig-telemetry-deviations-ce16800</capability>\n    " +
			"<capability>http://openconfig.net/yang/telemetry-types?module=openconfig-telemetry-types&amp;revision=2017-08-24</capability>\n    " +
			"<capability>http://openconfig.net/yang/transport-types?module=openconfig-transport-types&amp;revision=2018-05-16</capability>\n    " +
			"<capability>http://openconfig.net/yang/types/inet?module=openconfig-inet-types&amp;revision=2019-04-25</capability>\n    " +
			"<capability>http://openconfig.net/yang/types/yang?module=openconfig-yang-types&amp;revision=2018-04-24</capability>\n    " +
			"<capability>http://openconfig.net/yang/vlan?module=openconfig-vlan&amp;revision=2019-04-16&amp;deviations=huawei-openconfig-vlan-deviations-CE6866</capability>\n    " +
			"<capability>http://openconfig.net/yang/vlan-types?module=openconfig-vlan-types&amp;revision=2019-01-31</capability>\n    " +
			"<capability>http://www.huawei.com/netconf/vrp/huawei-hpe?module=huawei-hpe&amp;revision=2020-10-20</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-aaa?module=huawei-aaa&amp;revision=2021-03-17&amp;deviations=huawei-aaa-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-aaa-deviations-CE6866?module=huawei-aaa-deviations-CE6866&amp;revision=2019-11-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-aaa-service?module=huawei-aaa-service&amp;revision=2020-03-02&amp;deviations=huawei-aaa-service-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-aaa-service-deviations-CE6866?module=huawei-aaa-service-deviations-CE6866&amp;revision=2019-11-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-acl?module=huawei-acl&amp;revision=2019-06-23&amp;deviations=huawei-acl-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-acl-deviations-CE6866?module=huawei-acl-deviations-CE6866&amp;revision=2019-06-23</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ai-fabric?module=huawei-ai-fabric&amp;revision=2020-08-25</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ai-fabric-notification?module=huawei-ai-fabric-notification&amp;revision=2020-07-07</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-analysis-collector?module=huawei-analysis-collector&amp;revision=2020-03-27&amp;deviations=huawei-analysis-collector-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-analysis-collector-deviations-CE6866?module=huawei-analysis-collector-deviations-CE6866&amp;revision=2020-11-27</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-anyflow?module=huawei-anyflow&amp;revision=2020-03-27&amp;deviations=huawei-anyflow-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-anyflow-deviations-CE6866?module=huawei-anyflow-deviations-CE6866&amp;revision=2020-03-09</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-arp?module=huawei-arp&amp;revision=2020-08-20&amp;deviations=huawei-arp-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-arp-deviations-CE6866?module=huawei-arp-deviations-CE6866&amp;revision=2020-05-11</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-arp-fwd?module=huawei-arp-fwd&amp;revision=2021-04-16&amp;deviations=huawei-arp-fwd-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-arp-fwd-deviations-CE6866?module=huawei-arp-fwd-deviations-CE6866&amp;revision=2019-11-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-bd?module=huawei-bd&amp;revision=2021-01-26&amp;deviations=huawei-bd-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-bd-deviations-CE6866?module=huawei-bd-deviations-CE6866&amp;revision=2020-04-29</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-bfd?module=huawei-bfd&amp;revision=2021-03-22&amp;deviations=huawei-bfd-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-bfd-deviations-CE6866?module=huawei-bfd-deviations-CE6866&amp;revision=2020-02-20</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-bfd-fwm?module=huawei-bfd-fwm&amp;revision=2020-11-17</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-bfd-notification?module=huawei-bfd-notification&amp;revision=2019-07-08&amp;deviations=huawei-bfd-notification-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-bfd-notification-deviations-CE6866?module=huawei-bfd-notification-deviations-CE6866&amp;revision=2021-07-16</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-bgp?module=huawei-bgp&amp;revision=2021-02-03&amp;deviations=huawei-bgp-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-bgp-deviations-CE6866?module=huawei-bgp-deviations-CE6866&amp;revision=2020-04-20</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-bgp-evpn?module=huawei-bgp-evpn&amp;revision=2020-04-07&amp;deviations=huawei-bgp-evpn-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-bgp-evpn-deviations-CE6866?module=huawei-bgp-evpn-deviations-CE6866&amp;revision=2020-04-27</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-bgp-link-state?module=huawei-bgp-link-state&amp;revision=2020-02-25&amp;deviations=huawei-bgp-link-state-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-bgp-link-state-deviations-CE6866?module=huawei-bgp-link-state-deviations-CE6866&amp;revision=2020-12-10</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-bgp-maintenance?module=huawei-bgp-maintenance&amp;revision=2020-11-12&amp;deviations=huawei-bgp-maintenance-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-bgp-maintenance-deviations-CE6866?module=huawei-bgp-maintenance-deviations-CE6866&amp;revision=2020-11-20</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-bgp-routing-table?module=huawei-bgp-routing-table&amp;revision=2020-02-25&amp;deviations=huawei-bgp-routing-table-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-bgp-routing-table-deviations-CE6866?module=huawei-bgp-routing-table-deviations-CE6866&amp;revision=2020-04-28</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-bgp-rpc?module=huawei-bgp-rpc&amp;revision=2020-11-04&amp;deviations=huawei-bgp-rpc-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-bgp-rpc-deviations-CE6866?module=huawei-bgp-rpc-deviations-CE6866&amp;revision=2020-11-05</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-bmp?module=huawei-bmp&amp;revision=2021-03-02&amp;deviations=huawei-bmp-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-bmp-deviations-CE6866?module=huawei-bmp-deviations-CE6866&amp;revision=2021-05-07</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-capture?module=huawei-capture&amp;revision=2020-01-11&amp;deviations=huawei-capture-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-capture-deviations-CE6866?module=huawei-capture-deviations-CE6866&amp;revision=2017-12-23</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-cli?module=huawei-cli&amp;revision=2019-10-26&amp;deviations=huawei-cli-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-cli-deviations-CE6866?module=huawei-cli-deviations-CE6866&amp;revision=2019-11-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-codesign?module=huawei-codesign&amp;revision=2021-03-10&amp;deviations=huawei-codesign-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-codesign-deviations-CE6866?module=huawei-codesign-deviations-CE6866&amp;revision=2021-05-07</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-cpu-memory?module=huawei-cpu-memory&amp;revision=2021-02-08</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-cpu-memory-notification?module=huawei-cpu-memory-notification&amp;revision=2020-12-07&amp;deviations=huawei-cpu-memory-notification-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-cpu-memory-notification-deviations-CE6866?module=huawei-cpu-memory-notification-deviations-CE6866&amp;revision=2021-05-07</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-dcb?module=huawei-dcb&amp;revision=2021-01-14&amp;deviations=huawei-dcb-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-dcb-deviations-CE6866?module=huawei-dcb-deviations-CE6866&amp;revision=2020-05-29</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-dcb-notification?module=huawei-dcb-notification&amp;revision=2020-07-08</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-devm?module=huawei-devm&amp;revision=2021-01-06&amp;deviations=huawei-devm-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-devm-deviations-CE6866?module=huawei-devm-deviations-CE6866&amp;revision=2019-11-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-dhcp?module=huawei-dhcp&amp;revision=2020-12-24&amp;deviations=huawei-dhcp-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-dhcp-deviations-CE6866?module=huawei-dhcp-deviations-CE6866&amp;revision=2019-11-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-dhcpv6?module=huawei-dhcpv6&amp;revision=2020-04-29&amp;deviations=huawei-dhcpv6-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-dhcpv6-deviations-CE6866?module=huawei-dhcpv6-deviations-CE6866&amp;revision=2019-11-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-diagnostic-tools?module=huawei-diagnostic-tools&amp;revision=2021-05-11&amp;deviations=huawei-diagnostic-tools-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-diagnostic-tools-deviations-CE6866?module=huawei-diagnostic-tools-deviations-CE6866&amp;revision=2020-08-24</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-direct-route-vlink?module=huawei-direct-route-vlink&amp;revision=2019-07-15&amp;deviations=huawei-direct-route-vlink-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-direct-route-vlink-deviations-CE6866?module=huawei-direct-route-vlink-deviations-CE6866&amp;revision=2019-07-15</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-dns?module=huawei-dns&amp;revision=2021-01-19&amp;deviations=huawei-dns-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-dns-deviations-CE6866?module=huawei-dns-deviations-CE6866&amp;revision=2019-11-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-driver?module=huawei-driver&amp;revision=2021-05-06&amp;deviations=huawei-driver-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-driver-deviations-CE6866?module=huawei-driver-deviations-CE6866&amp;revision=2020-08-10</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-driver-monitor-notif?module=huawei-driver-monitor-notif&amp;revision=2020-07-20</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-driver-notification?module=huawei-driver-notification&amp;revision=2020-09-10&amp;deviations=huawei-driver-notification-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-driver-notification-deviations-CE6866?module=huawei-driver-notification-deviations-CE6866&amp;revision=2020-04-21</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-dsa?module=huawei-dsa&amp;revision=2019-05-01</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-eai-model?module=huawei-eai-model&amp;revision=2020-02-14</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-eca?module=huawei-eca&amp;revision=2021-03-25</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ecc?module=huawei-ecc&amp;revision=2019-05-02</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ethernet?module=huawei-ethernet&amp;revision=2020-05-14&amp;deviations=huawei-ethernet-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ethernet-deviations-CE6866?module=huawei-ethernet-deviations-CE6866&amp;revision=2020-04-14</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-evpl?module=huawei-evpl&amp;revision=2020-07-21&amp;deviations=huawei-evpl-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-evpl-deviations-CE6866?module=huawei-evpl-deviations-CE6866&amp;revision=2020-05-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-evpn?module=huawei-evpn&amp;revision=2020-05-04&amp;deviations=huawei-evpn-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-evpn-deviations-CE6866?module=huawei-evpn-deviations-CE6866&amp;revision=2020-05-08</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-extension?module=huawei-extension&amp;revision=2019-12-13</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-fib?module=huawei-fib&amp;revision=2021-04-16&amp;deviations=huawei-fib-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-fib-deviations-CE6866?module=huawei-fib-deviations-CE6866&amp;revision=2019-11-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-file-notification?module=huawei-file-notification&amp;revision=2020-08-25</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-file-operation?module=huawei-file-operation&amp;revision=2021-06-17&amp;deviations=huawei-file-operation-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-file-operation-deviations-CE6866?module=huawei-file-operation-deviations-CE6866&amp;revision=2020-05-05</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-fm?module=huawei-fm&amp;revision=2020-06-04&amp;deviations=huawei-fm-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-fm-deviations-CE6866?module=huawei-fm-deviations-CE6866&amp;revision=2020-05-24</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ftpc?module=huawei-ftpc&amp;revision=2020-02-26</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ftps?module=huawei-ftps&amp;revision=2019-07-01&amp;deviations=huawei-ftps-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ftps-deviations-CE6866?module=huawei-ftps-deviations-CE6866&amp;revision=2019-11-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-fwm-notification?module=huawei-fwm-notification&amp;revision=2020-06-02</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-fwm-resource?module=huawei-fwm-resource&amp;revision=2020-09-01&amp;deviations=huawei-fwm-resource-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-gre?module=huawei-gre&amp;revision=2020-05-18&amp;deviations=huawei-gre-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-gre-deviations-CE6866?module=huawei-gre-deviations-CE6866&amp;revision=2020-05-10</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-grpc?module=huawei-grpc&amp;revision=2020-06-18&amp;deviations=huawei-grpc-deviations-ce16800</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-grpc-deviations-ce16800?module=huawei-grpc-deviations-ce16800&amp;revision=2020-05-22</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-hardware-type?module=huawei-hardware-type&amp;revision=2020-03-27</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-hips?module=huawei-hips&amp;revision=2020-07-20</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-hips-deviations-CE6866?module=huawei-hips-deviations-CE6866&amp;revision=2019-11-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-host-security?module=huawei-host-security&amp;revision=2021-03-04&amp;deviations=huawei-host-security-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-host-security-deviations-CE6866?module=huawei-host-security-deviations-CE6866&amp;revision=2019-11-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-host-security-notif?module=huawei-host-security-notif&amp;revision=2020-10-13</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-http?module=huawei-http&amp;revision=2020-07-21</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-hwtacacs?module=huawei-hwtacacs&amp;revision=2020-07-06&amp;deviations=huawei-hwtacacs-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-hwtacacs-deviations-CE6866?module=huawei-hwtacacs-deviations-CE6866&amp;revision=2019-11-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ietf-interfaces-deviations-CE6866?module=huawei-ietf-interfaces-deviations-CE6866&amp;revision=2020-05-12</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ietf-ip-deviations-CE6866?module=huawei-ietf-ip-deviations-CE6866&amp;revision=2020-05-12</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ietf-netconf-acm-deviations-CE6866?module=huawei-ietf-netconf-acm-deviations-CE6866&amp;revision=2019-05-25</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ietf-netconf-ext?module=huawei-ietf-netconf-ext&amp;revision=2019-05-25</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ietf-netconf-monitoring-deviations-CE6866?module=huawei-ietf-netconf-monitoring-deviations-CE6866&amp;revision=2019-05-25</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ietf-netconf-notifications-deviations-CE6866?module=huawei-ietf-netconf-notifications-deviations-CE6866&amp;revision=2019-05-25</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ifm?module=huawei-ifm&amp;revision=2021-01-25&amp;deviations=huawei-ifm-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ifm-deviations-CE6866?module=huawei-ifm-deviations-CE6866&amp;revision=2020-04-26</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ifm-ip-statistics?module=huawei-ifm-ip-statistics&amp;revision=2020-04-01&amp;deviations=huawei-ifm-ip-statistics-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ifm-ip-statistics-deviations-CE6866?module=huawei-ifm-ip-statistics-deviations-CE6866&amp;revision=2020-08-25</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ifm-notification?module=huawei-ifm-notification&amp;revision=2020-05-30&amp;deviations=huawei-ifm-notification-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ifm-notification-deviations-CE6866?module=huawei-ifm-notification-deviations-CE6866&amp;revision=2020-05-30</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ifm-phy-notification?module=huawei-ifm-phy-notification&amp;revision=2020-07-15</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ifm-trunk?module=huawei-ifm-trunk&amp;revision=2020-02-14&amp;deviations=huawei-ifm-trunk-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ifm-trunk-deviations-CE6866?module=huawei-ifm-trunk-deviations-CE6866&amp;revision=2020-04-26</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ifm-trunk-notification?module=huawei-ifm-trunk-notification&amp;revision=2020-08-12</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-igmp-mld?module=huawei-igmp-mld&amp;revision=2021-02-24&amp;deviations=huawei-igmp-mld-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-igmp-mld-deviations-CE6866?module=huawei-igmp-mld-deviations-CE6866&amp;revision=2019-11-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-igmp-mld-snooping?module=huawei-igmp-mld-snooping&amp;revision=2020-05-21&amp;deviations=huawei-igmp-mld-snooping-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-igmp-mld-snooping-deviations-CE6866?module=huawei-igmp-mld-snooping-deviations-CE6866&amp;revision=2019-11-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ioam?module=huawei-ioam&amp;revision=2020-03-27&amp;deviations=huawei-ioam-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ioam-deviations-CE6866?module=huawei-ioam-deviations-CE6866&amp;revision=2020-09-11</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ip?module=huawei-ip&amp;revision=2020-06-30&amp;deviations=huawei-ip-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ip-cga?module=huawei-ip-cga&amp;revision=2020-02-14</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ip-deviations-CE6866?module=huawei-ip-deviations-CE6866&amp;revision=2020-04-26</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ipv6-nd?module=huawei-ipv6-nd&amp;revision=2021-02-02&amp;deviations=huawei-ipv6-nd-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ipv6-nd-deviations-CE6866?module=huawei-ipv6-nd-deviations-CE6866&amp;revision=2019-11-24</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ipv6-policy?module=huawei-ipv6-policy&amp;revision=2020-02-14</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-isis?module=huawei-isis&amp;revision=2020-08-10&amp;deviations=huawei-isis-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-isis-deviations-CE6866?module=huawei-isis-deviations-CE6866&amp;revision=2020-12-10</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-keychain?module=huawei-keychain&amp;revision=2021-02-01</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-l2vpn?module=huawei-l2vpn&amp;revision=2020-10-22&amp;deviations=huawei-l2vpn-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-l2vpn-deviations-CE6866?module=huawei-l2vpn-deviations-CE6866&amp;revision=2020-05-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-l3-multicast?module=huawei-l3-multicast&amp;revision=2019-03-30&amp;deviations=huawei-l3-multicast-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-l3-multicast-deviations-CE6866?module=huawei-l3-multicast-deviations-CE6866&amp;revision=2019-11-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-l3vpn?module=huawei-l3vpn&amp;revision=2020-03-23&amp;deviations=huawei-l3vpn-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-l3vpn-deviations-CE6866?module=huawei-l3vpn-deviations-CE6866&amp;revision=2020-04-20</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-lacp?module=huawei-lacp&amp;revision=2020-02-18&amp;deviations=huawei-lacp-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-lacp-deviations-CE6866?module=huawei-lacp-deviations-CE6866&amp;revision=2020-05-18</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-license?module=huawei-license&amp;revision=2020-03-07&amp;deviations=huawei-license-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-license-deviations-CE6866?module=huawei-license-deviations-CE6866&amp;revision=2020-06-11</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-lldp?module=huawei-lldp&amp;revision=2021-01-07&amp;deviations=huawei-lldp-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-lldp-deviations-CE6866?module=huawei-lldp-deviations-CE6866&amp;revision=2020-04-14</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-loadbalance?module=huawei-loadbalance&amp;revision=2020-06-16&amp;deviations=huawei-loadbalance-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-loadbalance-deviations-CE6866?module=huawei-loadbalance-deviations-CE6866&amp;revision=2019-11-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-m-lag?module=huawei-m-lag&amp;revision=2020-06-02&amp;deviations=huawei-m-lag-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-m-lag-deviations-CE6866?module=huawei-m-lag-deviations-CE6866&amp;revision=2020-10-14</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-m-lag-notification?module=huawei-m-lag-notification&amp;revision=2020-07-08</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-mac?module=huawei-mac&amp;revision=2020-08-07&amp;deviations=huawei-mac-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-mac-deviations-CE6866?module=huawei-mac-deviations-CE6866&amp;revision=2020-05-07</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-mac-flapping-detect?module=huawei-mac-flapping-detect&amp;revision=2020-04-24&amp;deviations=huawei-mac-flapping-detect-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-mac-flapping-detect-deviations-CE6866?module=huawei-mac-flapping-detect-deviations-CE6866&amp;revision=2020-04-29</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-mac-fwm-notification?module=huawei-mac-fwm-notification&amp;revision=2020-12-08</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-macsec?module=huawei-macsec&amp;revision=2020-06-01&amp;deviations=huawei-macsec-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-macsec-deviations-CE6866?module=huawei-macsec-deviations-CE6866&amp;revision=2019-11-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-masterkey?module=huawei-masterkey&amp;revision=2020-03-20</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-masterkey-notification?module=huawei-masterkey-notification&amp;revision=2020-08-25</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-md-cli?module=huawei-md-cli&amp;revision=2020-03-12</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-mirror?module=huawei-mirror&amp;revision=2020-07-29&amp;deviations=huawei-mirror-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-mirror-deviations-CE6866?module=huawei-mirror-deviations-CE6866&amp;revision=2020-06-19</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-module-management?module=huawei-module-management&amp;revision=2021-03-24&amp;deviations=huawei-module-management-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-module-management-deviations-CE6866?module=huawei-module-management-deviations-CE6866&amp;revision=2021-05-07</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-monitor-group?module=huawei-monitor-group&amp;revision=2020-03-09&amp;deviations=huawei-monitor-group-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-monitor-group-deviations-CE6866?module=huawei-monitor-group-deviations-CE6866&amp;revision=2019-04-28</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-monitor-link?module=huawei-monitor-link&amp;revision=2020-11-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-mpls?module=huawei-mpls&amp;revision=2020-07-02&amp;deviations=huawei-mpls-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-mpls-deviations-CE6866?module=huawei-mpls-deviations-CE6866&amp;revision=2020-05-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-mpls-ldp?module=huawei-mpls-ldp&amp;revision=2020-09-23&amp;deviations=huawei-mpls-ldp-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-mpls-ldp-deviations-CE6866?module=huawei-mpls-ldp-deviations-CE6866&amp;revision=2019-03-27</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-mpls-te?module=huawei-mpls-te&amp;revision=2020-09-23&amp;deviations=huawei-mpls-te-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-mpls-te-bfd?module=huawei-mpls-te-bfd&amp;revision=2020-09-24&amp;deviations=huawei-mpls-te-bfd-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-mpls-te-bfd-deviations-CE6866?module=huawei-mpls-te-bfd-deviations-CE6866&amp;revision=2020-12-10</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-mpls-te-deviations-CE6866?module=huawei-mpls-te-deviations-CE6866&amp;revision=2020-12-10</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-msdp?module=huawei-msdp&amp;revision=2021-03-04&amp;deviations=huawei-msdp-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-msdp-deviations-CE6866?module=huawei-msdp-deviations-CE6866&amp;revision=2019-11-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-mstp?module=huawei-mstp&amp;revision=2019-04-23&amp;deviations=huawei-mstp-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-mstp-deviations-CE6866?module=huawei-mstp-deviations-CE6866&amp;revision=2019-04-23</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-multicast?module=huawei-multicast&amp;revision=2020-02-14&amp;deviations=huawei-multicast-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-multicast-deviations-CE6866?module=huawei-multicast-deviations-CE6866&amp;revision=2019-11-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-nac-group?module=huawei-nac-group&amp;revision=2021-01-28&amp;deviations=huawei-nac-group-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-nac-group-deviations-CE6866?module=huawei-nac-group-deviations-CE6866&amp;revision=2019-11-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-nd-notification?module=huawei-nd-notification&amp;revision=2020-05-28&amp;deviations=huawei-nd-notification-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-nd-notification-deviations-CE6866?module=huawei-nd-notification-deviations-CE6866&amp;revision=2019-03-01</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ndb-notification?module=huawei-ndb-notification&amp;revision=2020-10-19</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-netconf?module=huawei-netconf&amp;revision=2020-02-22&amp;deviations=huawei-netconf-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-netconf-client-notif?module=huawei-netconf-client-notif&amp;revision=2021-04-02&amp;deviations=huawei-netconf-client-notif-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-netconf-client-notif-deviations-CE6866?module=huawei-netconf-client-notif-deviations-CE6866&amp;revision=2021-04-02</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-netconf-deviations-CE6866?module=huawei-netconf-deviations-CE6866&amp;revision=2020-06-12</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-netconf-metadata?module=huawei-netconf-metadata&amp;revision=2019-05-27</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-netconf-sync?module=huawei-netconf-sync&amp;revision=2020-07-02&amp;deviations=huawei-netconf-sync-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-netconf-sync-deviations-CE6866?module=huawei-netconf-sync-deviations-CE6866&amp;revision=2021-01-18</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-netstream?module=huawei-netstream&amp;revision=2020-03-10&amp;deviations=huawei-netstream-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-netstream-deviations-CE6866?module=huawei-netstream-deviations-CE6866&amp;revision=2021-05-29</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-network-instance?module=huawei-network-instance&amp;revision=2020-03-10&amp;deviations=huawei-network-instance-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-network-instance-deviations-CE6866?module=huawei-network-instance-deviations-CE6866&amp;revision=2020-04-20</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-notifications-deviations-CE6866?module=huawei-notifications-deviations-CE6866&amp;revision=2019-06-17</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-nqa?module=huawei-nqa&amp;revision=2021-04-29&amp;deviations=huawei-nqa-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-nqa-deviations-CE6866?module=huawei-nqa-deviations-CE6866&amp;revision=2020-08-24</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ntp?module=huawei-ntp&amp;revision=2021-06-02&amp;deviations=huawei-ntp-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ntp-deviations-CE6866?module=huawei-ntp-deviations-CE6866&amp;revision=2020-05-12</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-nvo3?module=huawei-nvo3&amp;revision=2020-03-06&amp;deviations=huawei-nvo3-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-nvo3-deviations-CE6866?module=huawei-nvo3-deviations-CE6866&amp;revision=2020-04-30</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-nvo3-statistics?module=huawei-nvo3-statistics&amp;revision=2020-03-30&amp;deviations=huawei-nvo3-statistics-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-nvo3-statistics-deviations-CE6866?module=huawei-nvo3-statistics-deviations-CE6866&amp;revision=2020-04-30</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-openconfig-acl-deviations-CE6866?module=huawei-openconfig-acl-deviations-CE6866&amp;revision=2019-06-23</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-openconfig-if-aggregate-deviations-CE6866?module=huawei-openconfig-if-aggregate-deviations-CE6866&amp;revision=2020-06-17</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-openconfig-if-ethernet-deviations-CE6866?module=huawei-openconfig-if-ethernet-deviations-CE6866&amp;revision=2020-05-12</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-openconfig-if-ip-deviations-CE6866?module=huawei-openconfig-if-ip-deviations-CE6866&amp;revision=2020-05-12</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-openconfig-interfaces-deviations-CE6866?module=huawei-openconfig-interfaces-deviations-CE6866&amp;revision=2020-05-12</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-openconfig-lacp-deviations-CE6866?module=huawei-openconfig-lacp-deviations-CE6866&amp;revision=2020-05-20</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-openconfig-lldp-deviations-CE6866?module=huawei-openconfig-lldp-deviations-CE6866&amp;revision=2020-05-12</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-openconfig-platform-deviations-CE6866?module=huawei-openconfig-platform-deviations-CE6866&amp;revision=2019-06-09</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-openconfig-platform-psu-deviations-CE6866?module=huawei-openconfig-platform-psu-deviations-CE6866&amp;revision=2019-06-09</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-openconfig-platform-transceiver-deviations-CE6866?module=huawei-openconfig-platform-transceiver-deviations-CE6866&amp;revision=2019-06-09</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-openconfig-telemetry-deviations-ce16800?module=huawei-openconfig-telemetry-deviations-ce16800&amp;revision=2021-05-07</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-openconfig-telemetry-ext?module=huawei-openconfig-telemetry-ext&amp;revision=2020-01-10&amp;deviations=huawei-openconfig-telemetry-ext-deviations-ce16800</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-openconfig-telemetry-ext-deviations-ce16800?module=huawei-openconfig-telemetry-ext-deviations-ce16800&amp;revision=2021-05-07</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-openconfig-vlan-deviations-CE6866?module=huawei-openconfig-vlan-deviations-CE6866&amp;revision=2020-05-12</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-openflow-agent?module=huawei-openflow-agent&amp;revision=2020-06-19</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ops?module=huawei-ops&amp;revision=2021-05-08&amp;deviations=huawei-ops-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ops-deviations-CE6866?module=huawei-ops-deviations-CE6866&amp;revision=2020-06-03</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ospfv2?module=huawei-ospfv2&amp;revision=2020-07-03&amp;deviations=huawei-ospfv2-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ospfv2-deviations-CE6866?module=huawei-ospfv2-deviations-CE6866&amp;revision=2019-04-04</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ospfv3?module=huawei-ospfv3&amp;revision=2020-03-13&amp;deviations=huawei-ospfv3-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ospfv3-deviations-CE6866?module=huawei-ospfv3-deviations-CE6866&amp;revision=2019-04-04</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-packetevent?module=huawei-packetevent&amp;revision=2020-03-27</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-patch?module=huawei-patch&amp;revision=2021-03-24&amp;deviations=huawei-patch-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-patch-deviations-CE6866?module=huawei-patch-deviations-CE6866&amp;revision=2021-05-07</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-patch-notification?module=huawei-patch-notification&amp;revision=2021-07-21</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-pbr?module=huawei-pbr&amp;revision=2020-03-14&amp;deviations=huawei-pbr-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-pbr-deviations-CE6866?module=huawei-pbr-deviations-CE6866&amp;revision=2020-06-19</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-pic?module=huawei-pic&amp;revision=2021-01-06&amp;deviations=huawei-pic-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-pic-deviations-CE6866?module=huawei-pic-deviations-CE6866&amp;revision=2019-11-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-pic-notification?module=huawei-pic-notification&amp;revision=2021-01-06&amp;deviations=huawei-pic-notification-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-pic-notification-deviations-CE6866?module=huawei-pic-notification-deviations-CE6866&amp;revision=2020-04-21</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-pim?module=huawei-pim&amp;revision=2020-03-16&amp;deviations=huawei-pim-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-pim-deviations-CE6866?module=huawei-pim-deviations-CE6866&amp;revision=2019-11-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-pki?module=huawei-pki&amp;revision=2021-01-06&amp;deviations=huawei-pki-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-pki-deviations-CE6866?module=huawei-pki-deviations-CE6866&amp;revision=2021-01-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-pm?module=huawei-pm&amp;revision=2019-12-16</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-port-group?module=huawei-port-group&amp;revision=2019-04-17</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-pp4?module=huawei-pp4&amp;revision=2020-03-06&amp;deviations=huawei-pp4-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-pp4-deviations-CE6866?module=huawei-pp4-deviations-CE6866&amp;revision=2020-03-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-pp6?module=huawei-pp6&amp;revision=2020-03-16&amp;deviations=huawei-pp6-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-pp6-deviations-CE6866?module=huawei-pp6-deviations-CE6866&amp;revision=2019-04-01</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-pub-type?module=huawei-pub-type&amp;revision=2020-04-01</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-qos?module=huawei-qos&amp;revision=2020-09-10&amp;deviations=huawei-qos-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-qos-bd?module=huawei-qos-bd&amp;revision=2020-06-11&amp;deviations=huawei-qos-bd-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-qos-bd-deviations-CE6866?module=huawei-qos-bd-deviations-CE6866&amp;revision=2020-04-07</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-qos-deviations-CE6866?module=huawei-qos-deviations-CE6866&amp;revision=2020-04-07</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-qos-l3vpn?module=huawei-qos-l3vpn&amp;revision=2020-02-27&amp;deviations=huawei-qos-l3vpn-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-qos-l3vpn-deviations-CE6866?module=huawei-qos-l3vpn-deviations-CE6866&amp;revision=2020-04-07</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-qos-notification?module=huawei-qos-notification&amp;revision=2020-09-01&amp;deviations=huawei-qos-notification-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-qos-notification-deviations-CE6866?module=huawei-qos-notification-deviations-CE6866&amp;revision=2020-04-07</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-radius?module=huawei-radius&amp;revision=2020-03-18&amp;deviations=huawei-radius-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-radius-deviations-CE6866?module=huawei-radius-deviations-CE6866&amp;revision=2019-11-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-radius-notification?module=huawei-radius-notification&amp;revision=2021-03-01</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-rgm?module=huawei-rgm&amp;revision=2019-11-28&amp;deviations=huawei-rgm-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-rgm-deviations-CE6866?module=huawei-rgm-deviations-CE6866&amp;revision=2019-11-28</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-route-monitor-group?module=huawei-route-monitor-group&amp;revision=2019-04-27&amp;deviations=huawei-route-monitor-group-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-route-monitor-group-deviations-CE6866?module=huawei-route-monitor-group-deviations-CE6866&amp;revision=2019-04-27</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-routing?module=huawei-routing&amp;revision=2019-04-27&amp;deviations=huawei-routing-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-routing-deviations-CE6866?module=huawei-routing-deviations-CE6866&amp;revision=2019-04-27</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-routing-notification?module=huawei-routing-notification&amp;revision=2021-02-21</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-routing-nqa?module=huawei-routing-nqa&amp;revision=2020-02-25&amp;deviations=huawei-routing-nqa-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-routing-nqa-deviations-CE6866?module=huawei-routing-nqa-deviations-CE6866&amp;revision=2020-02-25</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-routing-policy?module=huawei-routing-policy&amp;revision=2019-04-27&amp;deviations=huawei-routing-policy-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-routing-policy-acl?module=huawei-routing-policy-acl&amp;revision=2019-04-27</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-routing-policy-deviations-CE6866?module=huawei-routing-policy-deviations-CE6866&amp;revision=2019-04-27</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-rsa?module=huawei-rsa&amp;revision=2019-06-01</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-rsvp-interface?module=huawei-rsvp-interface&amp;revision=2020-07-11&amp;deviations=huawei-rsvp-interface-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-rsvp-interface-deviations-CE6866?module=huawei-rsvp-interface-deviations-CE6866&amp;revision=2020-08-14</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-secure-boot?module=huawei-secure-boot&amp;revision=2021-01-15</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-secure-boot-notification?module=huawei-secure-boot-notification&amp;revision=2021-02-20</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-sm2?module=huawei-sm2&amp;revision=2019-05-01&amp;deviations=huawei-sm2-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-sm2-deviations-CE6866?module=huawei-sm2-deviations-CE6866&amp;revision=2019-05-01</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-snmp?module=huawei-snmp&amp;revision=2020-04-13&amp;deviations=huawei-snmp-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-snmp-deviations-CE6866?module=huawei-snmp-deviations-CE6866&amp;revision=2019-04-23</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-socket?module=huawei-socket&amp;revision=2020-12-15&amp;deviations=huawei-socket-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-socket-deviations-CE6866?module=huawei-socket-deviations-CE6866&amp;revision=2020-03-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-software?module=huawei-software&amp;revision=2021-07-10&amp;deviations=huawei-software-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-software-deviations-CE6866?module=huawei-software-deviations-CE6866&amp;revision=2021-05-07</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-software-notification?module=huawei-software-notification&amp;revision=2020-06-23&amp;deviations=huawei-software-notification-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-software-notification-deviations-CE6866?module=huawei-software-notification-deviations-CE6866&amp;revision=2021-05-07</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-sshc?module=huawei-sshc&amp;revision=2020-07-02&amp;deviations=huawei-sshc-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-sshc-deviations-CE6866?module=huawei-sshc-deviations-CE6866&amp;revision=2019-05-01</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-sshs?module=huawei-sshs&amp;revision=2020-07-02&amp;deviations=huawei-sshs-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-sshs-deviations-CE6866?module=huawei-sshs-deviations-CE6866&amp;revision=2019-11-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ssl?module=huawei-ssl&amp;revision=2020-07-02&amp;deviations=huawei-ssl-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ssl-deviations-CE6866?module=huawei-ssl-deviations-CE6866&amp;revision=2019-11-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-storm-control?module=huawei-storm-control&amp;revision=2020-12-26&amp;deviations=huawei-storm-control-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-storm-control-deviations-CE6866?module=huawei-storm-control-deviations-CE6866&amp;revision=2019-11-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-storm-notification?module=huawei-storm-notification&amp;revision=2020-09-25</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-syslog?module=huawei-syslog&amp;revision=2021-05-26&amp;deviations=huawei-syslog-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-syslog-deviations-CE6866?module=huawei-syslog-deviations-CE6866&amp;revision=2020-02-19</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-system?module=huawei-system&amp;revision=2020-03-02</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-system-event-management?module=huawei-system-event-management&amp;revision=2020-05-08&amp;deviations=huawei-system-event-management-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-system-event-management-deviations-CE6866?module=huawei-system-event-management-deviations-CE6866&amp;revision=2021-05-07</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-system-event-mgmt-notif?module=huawei-system-event-mgmt-notif&amp;revision=2020-01-20&amp;deviations=huawei-system-event-mgmt-notif-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-system-event-mgmt-notif-deviations-CE6866?module=huawei-system-event-mgmt-notif-deviations-CE6866&amp;revision=2021-05-07</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-te?module=huawei-te&amp;revision=2020-04-02&amp;deviations=huawei-te-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-te-deviations-CE6866?module=huawei-te-deviations-CE6866&amp;revision=2020-12-10</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-te-interface?module=huawei-te-interface&amp;revision=2020-08-10&amp;deviations=huawei-te-interface-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-te-interface-deviations-CE6866?module=huawei-te-interface-deviations-CE6866&amp;revision=2020-12-10</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-telnetc?module=huawei-telnetc&amp;revision=2019-05-02</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-telnets?module=huawei-telnets&amp;revision=2020-03-04&amp;deviations=huawei-telnets-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-telnets-deviations-CE6866?module=huawei-telnets-deviations-CE6866&amp;revision=2019-11-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-tftpc?module=huawei-tftpc&amp;revision=2019-05-03</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-time-range?module=huawei-time-range&amp;revision=2019-05-23</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-tm?module=huawei-tm&amp;revision=2019-04-10</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-traffic-analysis?module=huawei-traffic-analysis&amp;revision=2020-03-27&amp;deviations=huawei-traffic-analysis-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-traffic-analysis-deviations-CE6866?module=huawei-traffic-analysis-deviations-CE6866&amp;revision=2020-03-09</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-trustem?module=huawei-trustem&amp;revision=2021-07-30&amp;deviations=huawei-trustem-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-trustem-deviations-CE6866?module=huawei-trustem-deviations-CE6866&amp;revision=2019-11-06</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-tty?module=huawei-tty&amp;revision=2020-03-02&amp;deviations=huawei-tty-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-tty-deviations-CE6866?module=huawei-tty-deviations-CE6866&amp;revision=2019-05-01</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-tunnel-management?module=huawei-tunnel-management&amp;revision=2020-01-10&amp;deviations=huawei-tunnel-management-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-tunnel-management-deviations-CE6866?module=huawei-tunnel-management-deviations-CE6866&amp;revision=2019-04-27</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-vlan?module=huawei-vlan&amp;revision=2020-02-07&amp;deviations=huawei-vlan-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-vlan-deviations-CE6866?module=huawei-vlan-deviations-CE6866&amp;revision=2019-04-23</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-vrrp?module=huawei-vrrp&amp;revision=2020-02-15&amp;deviations=huawei-vrrp-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-vrrp-deviations-CE6866?module=huawei-vrrp-deviations-CE6866&amp;revision=2020-03-19</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-vty?module=huawei-vty&amp;revision=2020-03-02&amp;deviations=huawei-vty-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-vty-deviations-CE6866?module=huawei-vty-deviations-CE6866&amp;revision=2019-05-01</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-vxlan-ext?module=huawei-vxlan-ext&amp;revision=2020-06-19&amp;deviations=huawei-vxlan-ext-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-vxlan-ext-deviations-CE6866?module=huawei-vxlan-ext-deviations-CE6866&amp;revision=2020-06-19</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-vxlan-ext-notification?module=huawei-vxlan-ext-notification&amp;revision=2021-01-22</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-vxlan-path-detect?module=huawei-vxlan-path-detect&amp;revision=2020-01-21&amp;deviations=huawei-vxlan-path-detect-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-vxlan-path-detect-deviations-CE6866?module=huawei-vxlan-path-detect-deviations-CE6866&amp;revision=2020-09-28</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-warranty?module=huawei-warranty&amp;revision=2020-04-24</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-warranty-notification?module=huawei-warranty-notification&amp;revision=2020-05-14</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-xpl?module=huawei-xpl&amp;revision=2019-04-27&amp;deviations=huawei-xpl-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-xpl-deviations-CE6866?module=huawei-xpl-deviations-CE6866&amp;revision=2019-04-27</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ztp?module=huawei-ztp&amp;revision=2021-04-12&amp;deviations=huawei-ztp-deviations-CE6866</capability>\n    " +
			"<capability>urn:huawei:yang:huawei-ztp-deviations-CE6866?module=huawei-ztp-deviations-CE6866&amp;revision=2020-03-04</capability>\n    " +
			"<capability>urn:ietf:params:xml:ns:netconf:base:1.0?module=ietf-netconf&amp;revision=2011-06-01&amp;features=writable-running,candidate,confirmed-commit,rollback-on-error,validate,startup,xpath,url</capability>\n    " +
			"<capability>urn:ietf:params:xml:ns:netconf:notification:1.0?module=notifications&amp;revision=2008-07-14&amp;deviations=huawei-notifications-deviations-CE6866</capability>\n    " +
			"<capability>urn:ietf:params:xml:ns:netmod:notification?module=nc-notifications&amp;revision=2008-07-14</capability>\n    " +
			"<capability>urn:ietf:params:xml:ns:yang:iana-if-type?module=iana-if-type&amp;revision=2017-01-19</capability>\n    " +
			"<capability>urn:ietf:params:xml:ns:yang:ietf-inet-types?module=ietf-inet-types&amp;revision=2013-07-15</capability>\n    " +
			"<capability>urn:ietf:params:xml:ns:yang:ietf-netconf-acm?module=ietf-netconf-acm&amp;revision=2018-02-14&amp;deviations=huawei-ietf-netconf-acm-deviations-CE6866</capability>\n    " +
			"<capability>urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring?module=ietf-netconf-monitoring&amp;revision=2010-10-04&amp;deviations=huawei-ietf-netconf-monitoring-deviations-CE6866</capability>\n    " +
			"<capability>urn:ietf:params:xml:ns:yang:ietf-netconf-notifications?module=ietf-netconf-notifications&amp;revision=2012-02-06&amp;deviations=huawei-ietf-netconf-notifications-deviations-CE6866</capability>\n    " +
			"<capability>urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults?module=ietf-netconf-with-defaults&amp;revision=2011-06-01</capability>\n    " +
			"<capability>urn:ietf:params:xml:ns:yang:ietf-yang-library?module=ietf-yang-library&amp;revision=2016-06-21</capability>\n    " +
			"<capability>urn:ietf:params:xml:ns:yang:ietf-yang-metadata?module=ietf-yang-metadata&amp;revision=2016-03-21</capability>\n    " +
			"<capability>urn:ietf:params:xml:ns:yang:ietf-yang-types?module=ietf-yang-types&amp;revision=2013-07-15</capability>\n  " +
			"</capabilities>\n  " +
			"<session-id>31598</session-id>\n" +
			"</hello>\n]]>]]>"),
		m.Expect("<?xml version=\"1.0\" encoding=\"UTF-8\"?><hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability><capability>urn:ietf:params:netconf:base:1.1</capability></capabilities></hello>"),
		m.Expect("]]>]]>"),
	}
)

func TestNetconf11Command(t *testing.T) {
	dialog := [][]m.Action{
		everyDayHuaweiHello,
		{
			m.Expect("\n#235\n"),
			m.Expect("<?xml version=\"1.0\" encoding=\"UTF-8\"?><rpc xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"1\"><get><filter type=\"subtree\"><nvo3 xmlns=\"urn:huawei:yang:huawei-nvo3\"><vni-instances></vni-instances></nvo3></filter></get></rpc>"),
			m.Expect("\n##\n"),
			m.Send("\n#30648\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<rpc-reply message-id=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n  <data>\n    <nvo3 xmlns=\"urn:huawei:yang:huawei-nvo3\">\n      <vni-instances>\n        <vni-instance>\n          <vni>810001</vni>\n     "),
			m.Send("     <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810002</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n      "),
			m.Send("    <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810003</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n       "),
			m.Send(" <vni-instance>\n          <vni>810004</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810005</vni>\n          <source-nve>Nve"),
			m.Send("1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810006</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>pe"),
			m.Send("er</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810007</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n    "),
			m.Send("      <vni>810008</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810009</vni>\n          <source-nve>Nve1</source-nve>\n     "),
			m.Send("     <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810010</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n  "),
			m.Send("      </vni-instance>\n        <vni-instance>\n          <vni>810011</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810012</v"),
			m.Send("ni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810013</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</stat"),
			m.Send("e>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810014</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance"),
			m.Send(">\n        <vni-instance>\n          <vni>810015</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810016</vni>\n          <sourc"),
			m.Send("e-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810017</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protoc"),
			m.Send("ol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810018</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-insta"),
			m.Send("nce>\n          <vni>810019</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810020</vni>\n          <source-nve>Nve1</source-n"),
			m.Send("ve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810021</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protoco"),
			m.Send("l-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810022</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>"),
			m.Send("810023</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810024</vni>\n          <source-nve>Nve1</source-nve>\n          <state"),
			m.Send(">up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810025</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni"),
			m.Send("-instance>\n        <vni-instance>\n          <vni>810026</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810027</vni>\n       "),
			m.Send("   <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810028</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n        "),
			m.Send("  <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810029</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <"),
			m.Send("vni-instance>\n          <vni>810030</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810031</vni>\n          <source-nve>Nve1<"),
			m.Send("/source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810032</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer"),
			m.Send("</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810033</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n      "),
			m.Send("    <vni>810034</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810035</vni>\n          <source-nve>Nve1</source-nve>\n       "),
			m.Send("   <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810036</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n    "),
			m.Send("    </vni-instance>\n        <vni-instance>\n          <vni>810038</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810039</vni"),
			m.Send(">\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810040</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>"),
			m.Send("\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810041</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n"),
			m.Send("        <vni-instance>\n          <vni>810042</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810043</vni>\n          <source-"),
			m.Send("nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810044</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol"),
			m.Send("-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810045</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instanc"),
			m.Send("e>\n          <vni>810046</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810047</vni>\n          <source-nve>Nve1</source-nve"),
			m.Send(">\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810048</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-"),
			m.Send("bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810049</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>81"),
			m.Send("0050</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810051</vni>\n          <source-nve>Nve1</source-nve>\n          <state>u"),
			m.Send("p</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810052</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-i"),
			m.Send("nstance>\n        <vni-instance>\n          <vni>810053</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810054</vni>\n         "),
			m.Send(" <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810055</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          "),
			m.Send("<protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810056</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vn"),
			m.Send("i-instance>\n          <vni>810057</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810058</vni>\n          <source-nve>Nve1</s"),
			m.Send("ource-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810059</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</"),
			m.Send("protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810060</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n        "),
			m.Send("  <vni>810061</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810062</vni>\n          <source-nve>Nve1</source-nve>\n         "),
			m.Send(" <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810063</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n      "),
			m.Send("  </vni-instance>\n        <vni-instance>\n          <vni>810064</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810065</vni>\n"),
			m.Send("          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810066</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n "),
			m.Send("         <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810067</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n  "),
			m.Send("      <vni-instance>\n          <vni>810068</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810069</vni>\n          <source-nv"),
			m.Send("e>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810070</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-b"),
			m.Send("gp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810071</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>"),
			m.Send("\n          <vni>810072</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810073</vni>\n          <source-nve>Nve1</source-nve>\n"),
			m.Send("          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810074</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bg"),
			m.Send("p>\n        </vni-instance>\n        <vni-instance>\n          <vni>810075</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>8100"),
			m.Send("76</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810077</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up<"),
			m.Send("/state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810078</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-ins"),
			m.Send("tance>\n        <vni-instance>\n          <vni>810079</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810080</vni>\n          <"),
			m.Send("source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810081</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <p"),
			m.Send("rotocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810082</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-"),
			m.Send("instance>\n          <vni>810083</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810084</vni>\n          <source-nve>Nve1</sou"),
			m.Send("rce-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810085</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</pr"),
			m.Send("otocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810086</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          "),
			m.Send("<vni>810087</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810088</vni>\n          <source-nve>Nve1</source-nve>\n          <"),
			m.Send("state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810089</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        "),
			m.Send("</vni-instance>\n        <vni-instance>\n          <vni>810090</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810091</vni>\n  "),
			m.Send("        <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810092</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n   "),
			m.Send("       <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810093</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n    "),
			m.Send("    <vni-instance>\n          <vni>810094</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810095</vni>\n          <source-nve>"),
			m.Send("Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810096</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp"),
			m.Send(">peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810097</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n "),
			m.Send("         <vni>810098</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810099</vni>\n          <source-nve>Nve1</source-nve>\n  "),
			m.Send("        <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810100</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>"),
			m.Send("\n        </vni-instance>\n        <vni-instance>\n          <vni>810101</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810102"),
			m.Send("</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810103</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</s"),
			m.Send("tate>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810104</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-insta"),
			m.Send("nce>\n        <vni-instance>\n          <vni>810110</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810147</vni>\n          <so"),
			m.Send("urce-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810150</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <pro"),
			m.Send("tocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810151</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-in"),
			m.Send("stance>\n          <vni>810152</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810153</vni>\n          <source-nve>Nve1</sourc"),
			m.Send("e-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810154</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</prot"),
			m.Send("ocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810155</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <v"),
			m.Send("ni>810156</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810157</vni>\n          <source-nve>Nve1</source-nve>\n          <st"),
			m.Send("ate>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810161</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </"),
			m.Send("vni-instance>\n        <vni-instance>\n          <vni>810162</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810191</vni>\n    "),
			m.Send("      <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810192</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n     "),
			m.Send("     <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810196</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n      "),
			m.Send("  <vni-instance>\n          <vni>810201</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810210</vni>\n          <source-nve>Nv"),
			m.Send("e1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810211</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>p"),
			m.Send("eer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810212</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n   "),
			m.Send("       <vni>810213</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810214</vni>\n          <source-nve>Nve1</source-nve>\n    "),
			m.Send("      <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810215</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n "),
			m.Send("       </vni-instance>\n        <vni-instance>\n          <vni>810223</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810234</"),
			m.Send("vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810297</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</sta"),
			m.Send("te>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810300</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instanc"),
			m.Send("e>\n        <vni-instance>\n          <vni>810301</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810335</vni>\n          <sour"),
			m.Send("ce-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810398</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <proto"),
			m.Send("col-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810408</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-inst"),
			m.Send("ance>\n          <vni>810410</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810411</vni>\n          <source-nve>Nve1</source-"),
			m.Send("nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810515</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protoc"),
			m.Send("ol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810532</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni"),
			m.Send(">810533</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810538</vni>\n          <source-nve>Nve1</source-nve>\n          <stat"),
			m.Send("e>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810542</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vn"),
			m.Send("i-instance>\n        <vni-instance>\n          <vni>810547</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810562</vni>\n      "),
			m.Send("    <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810576</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n       "),
			m.Send("   <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810577</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        "),
			m.Send("<vni-instance>\n          <vni>810584</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810595</vni>\n          <source-nve>Nve1"),
			m.Send("</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810597</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>pee"),
			m.Send("r</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810601</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n     "),
			m.Send("     <vni>810602</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810603</vni>\n          <source-nve>Nve1</source-nve>\n      "),
			m.Send("    <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810610</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n   "),
			m.Send("     </vni-instance>\n        <vni-instance>\n          <vni>810611</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810638</vn"),
			m.Send("i>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810642</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state"),
			m.Send(">\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810666</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>"),
			m.Send("\n        <vni-instance>\n          <vni>810668</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810677</vni>\n          <source"),
			m.Send("-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810686</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protoco"),
			m.Send("l-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810692</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instan"),
			m.Send("ce>\n          <vni>810695</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810800</vni>\n          <source-nve>Nve1</source-nv"),
			m.Send("e>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810801</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol"),
			m.Send("-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810802</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>"),
			m.Send("\n#12237\n\n        </vni-instance>\n        <vni-instance>\n          <vni>810803</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vn"),
			m.Send("i>810804</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810805</vni>\n          <source-nve>Nve1</source-nve>\n          <sta"),
			m.Send("te>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810806</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </v"),
			m.Send("ni-instance>\n        <vni-instance>\n          <vni>810807</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810808</vni>\n     "),
			m.Send("     <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810809</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n      "),
			m.Send("    <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810810</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n       "),
			m.Send(" <vni-instance>\n          <vni>810811</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810812</vni>\n          <source-nve>Nve"),
			m.Send("1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810825</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>pe"),
			m.Send("er</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810827</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n    "),
			m.Send("      <vni>810828</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810831</vni>\n          <source-nve>Nve1</source-nve>\n     "),
			m.Send("     <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810850</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n  "),
			m.Send("      </vni-instance>\n        <vni-instance>\n          <vni>810851</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810852</v"),
			m.Send("ni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810853</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</stat"),
			m.Send("e>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810854</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance"),
			m.Send(">\n        <vni-instance>\n          <vni>810859</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810861</vni>\n          <sourc"),
			m.Send("e-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810862</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protoc"),
			m.Send("ol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810863</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-insta"),
			m.Send("nce>\n          <vni>810864</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810866</vni>\n          <source-nve>Nve1</source-n"),
			m.Send("ve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810867</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protoco"),
			m.Send("l-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810868</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>"),
			m.Send("810901</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810903</vni>\n          <source-nve>Nve1</source-nve>\n          <state"),
			m.Send(">up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810904</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni"),
			m.Send("-instance>\n        <vni-instance>\n          <vni>810905</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810906</vni>\n       "),
			m.Send("   <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810907</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n        "),
			m.Send("  <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810908</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <"),
			m.Send("vni-instance>\n          <vni>810909</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810910</vni>\n          <source-nve>Nve1<"),
			m.Send("/source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810911</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer"),
			m.Send("</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810912</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n      "),
			m.Send("    <vni>810913</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810920</vni>\n          <source-nve>Nve1</source-nve>\n       "),
			m.Send("   <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>810999</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n    "),
			m.Send("    </vni-instance>\n        <vni-instance>\n          <vni>811260</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>811309</vni"),
			m.Send(">\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>811382</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>"),
			m.Send("\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>811524</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n"),
			m.Send("        <vni-instance>\n          <vni>811529</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>811557</vni>\n          <source-"),
			m.Send("nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>811600</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol"),
			m.Send("-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>811655</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instanc"),
			m.Send("e>\n          <vni>811664</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>811859</vni>\n          <source-nve>Nve1</source-nve"),
			m.Send(">\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>811901</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-"),
			m.Send("bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>811902</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>81"),
			m.Send("1999</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>812000</vni>\n          <source-nve>Nve1</source-nve>\n          <state>u"),
			m.Send("p</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>812602</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-i"),
			m.Send("nstance>\n        <vni-instance>\n          <vni>812614</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>812683</vni>\n         "),
			m.Send(" <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>812685</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          "),
			m.Send("<protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>812697</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vn"),
			m.Send("i-instance>\n          <vni>813000</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>813010</vni>\n          <source-nve>Nve1</s"),
			m.Send("ource-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>813397</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</"),
			m.Send("protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n          <vni>813666</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        <vni-instance>\n        "),
			m.Send("  <vni>813701</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n      </vni-instances>\n    </nvo3>\n  </data>\n</rpc-reply>\n##\n"),
		},
	}
	expected := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<rpc-reply message-id=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n  <data>\n    <nvo3 xmlns=\"urn:huawei:yang:huawei-nvo3\">\n      " +
		"<vni-instances>\n        " +
		"<vni-instance>\n          <vni>810001</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810002</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810003</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810004</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810005</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810006</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810007</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810008</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810009</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810010</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810011</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810012</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810013</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810014</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810015</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810016</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810017</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810018</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810019</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810020</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810021</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810022</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810023</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810024</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810025</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810026</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810027</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810028</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810029</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810030</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810031</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810032</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810033</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810034</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810035</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810036</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810038</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810039</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810040</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810041</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810042</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810043</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810044</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810045</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810046</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810047</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810048</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810049</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810050</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810051</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810052</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810053</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810054</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810055</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810056</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810057</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810058</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810059</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810060</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810061</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810062</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810063</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810064</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810065</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810066</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810067</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810068</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810069</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810070</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810071</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810072</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810073</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810074</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810075</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810076</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810077</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810078</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810079</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810080</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810081</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810082</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810083</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810084</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810085</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810086</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810087</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810088</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810089</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810090</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810091</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810092</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810093</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810094</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810095</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810096</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810097</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810098</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810099</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810100</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810101</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810102</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810103</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810104</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810110</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810147</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810150</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810151</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810152</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810153</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810154</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810155</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810156</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810157</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810161</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810162</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810191</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810192</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810196</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810201</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810210</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810211</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810212</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810213</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810214</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810215</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810223</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810234</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810297</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810300</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810301</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810335</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810398</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810408</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810410</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810411</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810515</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810532</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810533</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810538</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810542</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810547</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810562</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810576</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810577</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810584</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810595</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810597</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810601</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810602</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810603</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810610</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810611</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810638</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810642</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810666</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810668</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810677</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810686</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810692</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810695</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810800</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810801</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810802</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810803</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810804</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810805</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810806</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810807</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810808</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810809</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810810</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810811</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810812</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810825</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810827</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810828</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810831</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810850</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810851</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810852</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810853</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810854</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810859</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810861</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810862</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810863</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810864</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810866</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810867</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810868</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810901</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810903</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810904</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810905</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810906</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810907</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810908</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810909</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810910</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810911</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810912</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810913</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810920</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>810999</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>811260</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>811309</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>811382</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>811524</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>811529</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>811557</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>811600</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>811655</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>811664</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>811859</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>811901</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>811902</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>811999</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>812000</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>812602</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>812614</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>812683</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>812685</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>812697</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>813000</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>813010</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>813397</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>813666</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n        " +
		"<vni-instance>\n          <vni>813701</vni>\n          <source-nve>Nve1</source-nve>\n          <state>up</state>\n          <protocol-bgp>peer</protocol-bgp>\n        </vni-instance>\n      " +
		"</vni-instances>\n    </nvo3>\n  </data>\n</rpc-reply>"
	command := `<get><filter type="subtree"><nvo3 xmlns="urn:huawei:yang:huawei-nvo3"><vni-instances></vni-instances></nvo3></filter></get>`
	actions := m.ConcatMultipleSlices(dialog)
	m.RunDialog(t, func(connector streamer.Connector) device.Device {
		return NewDevice(connector)
	}, actions, command, expected)
}

func TestNetconf11CommandSimple(t *testing.T) {
	dialog := [][]m.Action{
		{
			m.Send("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">" +
				"<capabilities>" +
				"<capability>urn:ietf:params:netconf:base:1.0</capability>" +
				"<capability>urn:ietf:params:netconf:base:1.1</capability>" +
				"</capabilities>" +
				"<session-id>1</session-id>" +
				"</hello>\n]]>]]>"),
			m.Expect("<?xml version=\"1.0\" encoding=\"UTF-8\"?><hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability><capability>urn:ietf:params:netconf:base:1.1</capability></capabilities></hello>"),
			m.Expect("]]>]]>"),
			m.Expect("\n#123\n"),
			m.Expect("<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
				"<rpc xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"1\">" +
				"<get></get>" +
				"</rpc>"),
			m.Expect("\n##\n"),
			m.Send("\n#10\n"),
			m.Send("<rpc-reply"),
			m.Send("\n#16\n"),
			m.Send(" message-id=\"1\"\n"),
			m.Send("\n#98\n"),
			m.Send("     xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"),
			m.Send("  <data><olo>11111</olo></data>\n"),
			m.Send("</rpc-reply>"),
			m.Send("\n##\n"),
		},
	}
	expected := "<rpc-reply message-id=\"1\"\n     xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n  <data><olo>11111</olo></data>\n</rpc-reply>"
	command := "<get></get>"
	actions := m.ConcatMultipleSlices(dialog)
	m.RunDialog(t, func(connector streamer.Connector) device.Device {
		return NewDevice(connector)
	}, actions, command, expected)
}
