package console

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/harvester/harvester-installer/pkg/config"
	"github.com/harvester/harvester-installer/pkg/version"
	"github.com/harvester/harvester-installer/pkg/widgets"
)

const vipNeighborProbeTimeout = 1500 * time.Millisecond

var layerSentryProductionDefaultAddons = []string{
	"rancher_logging",
	"rancher_monitoring",
}

// ensureLayerSentryProductionAddons applies the stable LayerSentry production
// observability baseline without overriding any explicit installer choice.
// Experimental and hardware-specific add-ons remain bundled but opt-in.
func ensureLayerSentryProductionAddons(hvstConfig *config.HarvesterConfig) {
	if hvstConfig.Install.Addons == nil {
		hvstConfig.Install.Addons = make(map[string]config.Addon)
	}
	for _, name := range layerSentryProductionDefaultAddons {
		if _, explicitlyConfigured := hvstConfig.Install.Addons[name]; explicitlyConfigured {
			continue
		}
		hvstConfig.Install.Addons[name] = config.Addon{Enabled: true}
	}
}

func interactiveInstallModeOptions() ([]widgets.Option, error) {
	return []widgets.Option{
		{Value: config.ModeCreate, Text: fmt.Sprintf("Create a new %s cluster", version.ProductName)},
		{Value: config.ModeJoin, Text: fmt.Sprintf("Join an existing %s cluster", version.ProductName)},
	}, nil
}

func interactiveNetworkPanels() []string {
	return []string{
		askVlanIDPanel,
		askBondModePanel,
		addressPanel,
		addrMaskPanel,
		gatewayPanel,
		mtuPanel,
		askInterfacePanel,
	}
}

func interactiveVIPPanels() []string {
	return []string{vipTextPanel, vipPanel}
}

func validateManagementInterfaceSelection(ifaces []string) error {
	if len(ifaces) == 0 {
		return fmt.Errorf("must select at least one interface")
	}
	return nil
}

func parseStaticIPv4Address(address string) (net.IP, *net.IPNet, error) {
	if err := checkStaticRequiredString("address", address); err != nil {
		return nil, nil, err
	}

	ip, ipNet, err := net.ParseCIDR(address)
	if err != nil {
		ip = net.ParseIP(address)
		if ip == nil || ip.To4() == nil {
			return nil, nil, fmt.Errorf("%s is not a valid IPv4 address", address)
		}
		return ip.To4(), nil, nil
	}
	if ip.To4() == nil {
		return nil, nil, fmt.Errorf("%s is not a valid IPv4 address", address)
	}
	return ip.To4(), ipNet, nil
}

func validateStaticGateway(nodeIP, subnetMask, gateway string) error {
	if err := checkStaticRequiredString("gateway", gateway); err != nil {
		return err
	}
	if err := checkIP(gateway); err != nil {
		return err
	}
	ip := net.ParseIP(nodeIP).To4()
	gw := net.ParseIP(gateway).To4()
	if ip == nil {
		return fmt.Errorf("%s is not a valid IPv4 management address", nodeIP)
	}
	mask, err := ParseMask(subnetMask)
	if err != nil {
		return err
	}
	networkIP := ip.Mask(mask)
	network := &net.IPNet{IP: networkIP, Mask: mask}
	if !network.Contains(gw) {
		return fmt.Errorf("gateway %s is outside management network %s", gateway, network.String())
	}
	if gw.Equal(ip) {
		return fmt.Errorf("gateway must not be the same as management IP %s", nodeIP)
	}

	broadcast := make(net.IP, net.IPv4len)
	for i := 0; i < net.IPv4len; i++ {
		broadcast[i] = networkIP[i] | ^mask[i]
	}
	if gw.Equal(networkIP) || gw.Equal(broadcast) {
		return fmt.Errorf("gateway %s is not a usable host address in %s", gateway, network.String())
	}
	return nil
}

func normalizeStaticDNSList(ipList []string) ([]string, error) {
	normalized := make([]string, 0, len(ipList))
	seen := map[string]struct{}{}
	for _, raw := range ipList {
		value := strings.TrimSpace(raw)
		if value == "" {
			return nil, fmt.Errorf("DNS server entry must not be empty")
		}
		if err := checkIP(value); err != nil {
			return nil, err
		}
		canonical := net.ParseIP(value).To4().String()
		if _, exists := seen[canonical]; exists {
			return nil, fmt.Errorf("duplicate DNS server: %s", canonical)
		}
		seen[canonical] = struct{}{}
		normalized = append(normalized, canonical)
	}
	return normalized, nil
}

func validateStaticVIPAddress(vip, nodeIP, subnetMask string) error {
	if err := checkStaticRequiredString("VIP", vip); err != nil {
		return err
	}
	if err := checkIP(vip); err != nil {
		return fmt.Errorf("invalid VIP: %s", vip)
	}
	if vip == nodeIP {
		return fmt.Errorf("VIP must not be the same as management NIC's IP")
	}
	if nodeIP == "" || subnetMask == "" {
		return nil
	}

	ip := net.ParseIP(nodeIP).To4()
	vipIP := net.ParseIP(vip).To4()
	if ip == nil || vipIP == nil {
		return fmt.Errorf("VIP and management address must be IPv4")
	}
	mask, err := ParseMask(subnetMask)
	if err != nil {
		return err
	}
	networkIP := ip.Mask(mask)
	network := &net.IPNet{IP: networkIP, Mask: mask}
	if !network.Contains(vipIP) {
		return fmt.Errorf("VIP %s is outside management network %s", vip, network.String())
	}
	broadcast := make(net.IP, net.IPv4len)
	for i := 0; i < net.IPv4len; i++ {
		broadcast[i] = networkIP[i] | ^mask[i]
	}
	if vipIP.Equal(networkIP) || vipIP.Equal(broadcast) {
		return fmt.Errorf("VIP %s is not a usable host address in %s", vip, network.String())
	}
	return nil
}

func probeIPv4NeighborMAC(interfaceName, ipv4 string, timeout time.Duration) (net.HardwareAddr, error) {
	ip := net.ParseIP(ipv4)
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("%s is not a valid IPv4 address", ipv4)
	}
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("find management interface %s: %w", interfaceName, err)
	}

	deadline := time.Now().Add(timeout)
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: ip.To4(), Port: 9})
	if err != nil {
		return nil, fmt.Errorf("probe VIP %s: %w", ipv4, err)
	}
	_ = conn.SetWriteDeadline(deadline)
	_, writeErr := conn.Write([]byte{0})
	_ = conn.Close()
	if writeErr != nil {
		return nil, fmt.Errorf("probe VIP %s: %w", ipv4, writeErr)
	}

	for time.Now().Before(deadline) {
		neighbors, err := netlink.NeighList(link.Attrs().Index, netlink.FAMILY_V4)
		if err != nil {
			return nil, fmt.Errorf("read IPv4 neighbor table on %s: %w", interfaceName, err)
		}
		for _, neighbor := range neighbors {
			if neighbor.IP == nil || !neighbor.IP.Equal(ip) || len(neighbor.HardwareAddr) == 0 {
				continue
			}
			if neighbor.State == netlink.NUD_FAILED || neighbor.State == netlink.NUD_INCOMPLETE {
				continue
			}
			return neighbor.HardwareAddr, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, nil
}
