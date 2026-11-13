package netcfg

import (
	"net/netip"
	"testing"
)

func TestFindConflict(t *testing.T) {
	subnet := netip.MustParsePrefix("10.214.3.0/24")
	p := netip.MustParsePrefix
	a := netip.MustParseAddr
	cases := []struct {
		name     string
		routes   []route
		conflict bool
	}{
		{"typical home network", []route{
			{dst: p("0.0.0.0/0"), gw: a("192.168.1.1"), iface: "Wi-Fi"},
			{dst: p("192.168.1.0/24"), iface: "Wi-Fi"},
			{dst: p("192.168.1.20/32"), iface: "Wi-Fi"},
			{dst: p("224.0.0.0/4"), iface: "Wi-Fi"},
			{dst: p("255.255.255.255/32"), iface: "Wi-Fi"},
		}, false},
		{"full-tunnel VPN with split default routes", []route{
			{dst: p("0.0.0.0/0"), gw: a("192.168.1.1"), iface: "Wi-Fi"},
			{dst: p("0.0.0.0/1"), gw: a("10.8.0.1"), iface: "VPN"},
			{dst: p("128.0.0.0/1"), gw: a("10.8.0.1"), iface: "VPN"},
			{dst: p("10.8.0.0/24"), iface: "VPN"},
			{dst: p("203.0.113.9/32"), gw: a("192.168.1.1"), iface: "Wi-Fi"},
		}, false},
		{"corporate VPN routing all of 10/8", []route{{dst: p("10.0.0.0/8"), gw: a("172.16.0.1"), iface: "Corp"}}, false},
		{"another network with the same range", []route{{dst: p("10.214.3.0/24"), iface: "Ethernet"}}, true},
		{"this machine has an address inside the range", []route{{dst: p("10.214.3.77/32"), iface: "Ethernet"}}, true},
		{"a smaller network inside the range", []route{{dst: p("10.214.3.128/25"), iface: "Ethernet"}}, true},
		{"VPN gateway inside the range", []route{
			{dst: p("10.214.0.0/16"), iface: "VPN"},
			{dst: p("0.0.0.0/1"), gw: a("10.214.3.1"), iface: "VPN"},
		}, true},
		{"default gateway inside the range", []route{{dst: p("0.0.0.0/0"), gw: a("10.214.3.254"), iface: "Wi-Fi"}}, true},
		{"the adapter's own routes are ignored", []route{
			{dst: p("10.214.3.0/24"), iface: "Lanora"},
			{dst: p("10.214.3.5/32"), iface: "Lanora"},
			{dst: p("10.214.3.255/32"), iface: "Lanora"},
		}, false},
		{"neighbouring room range", []route{{dst: p("10.214.4.0/24"), iface: "Ethernet"}}, false},
	}
	for _, c := range cases {
		got := findConflict(subnet, c.routes, "Lanora")
		if (got != nil) != c.conflict {
			t.Errorf("%s: conflict = %v, want %v", c.name, got, c.conflict)
		}
		if got != nil && got.Error() == "" {
			t.Errorf("%s: empty message", c.name)
		}
	}
}
