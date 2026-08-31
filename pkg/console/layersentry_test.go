package console

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/harvester/harvester-installer/pkg/config"
)

func TestInteractiveInstallModeOptions(t *testing.T) {
	options, err := interactiveInstallModeOptions()
	require.NoError(t, err)
	require.Len(t, options, 2)
	require.Equal(t, config.ModeCreate, options[0].Value)
	require.Equal(t, "Create a new LayerSentry cluster", options[0].Text)
	require.Equal(t, config.ModeJoin, options[1].Value)
	require.Equal(t, "Join an existing LayerSentry cluster", options[1].Text)
	for _, option := range options {
		require.NotEqual(t, config.ModeInstall, option.Value)
	}
}

func TestInteractiveNetworkPanelsAreStaticOnly(t *testing.T) {
	panels := interactiveNetworkPanels()
	require.Contains(t, panels, askInterfacePanel)
	require.Contains(t, panels, addressPanel)
	require.Contains(t, panels, addrMaskPanel)
	require.Contains(t, panels, gatewayPanel)
	require.NotContains(t, panels, askNetworkMethodPanel)
}

func TestInteractiveVIPPanelsDoNotExposeDHCPOrMACInput(t *testing.T) {
	panels := interactiveVIPPanels()
	require.Equal(t, []string{vipTextPanel, vipPanel}, panels)
	require.NotContains(t, panels, askVipMethodPanel)
	require.NotContains(t, panels, vipHwAddrPanel)
}

func TestValidateManagementInterfaceSelection(t *testing.T) {
	require.Error(t, validateManagementInterfaceSelection(nil))
	require.NoError(t, validateManagementInterfaceSelection([]string{"eth0"}))
}

func TestParseStaticIPv4Address(t *testing.T) {
	ip, network, err := parseStaticIPv4Address("192.0.2.10")
	require.NoError(t, err)
	require.Equal(t, "192.0.2.10", ip.String())
	require.Nil(t, network)

	ip, network, err = parseStaticIPv4Address("192.0.2.10/24")
	require.NoError(t, err)
	require.Equal(t, "192.0.2.10", ip.String())
	require.NotNil(t, network)
	ones, bits := network.Mask.Size()
	require.Equal(t, 24, ones)
	require.Equal(t, 32, bits)

	for _, invalid := range []string{"", "not-an-ip", "2001:db8::10", "2001:db8::10/64"} {
		_, _, err = parseStaticIPv4Address(invalid)
		require.Error(t, err, invalid)
	}
}

func TestValidateStaticGateway(t *testing.T) {
	require.NoError(t, validateStaticGateway("192.0.2.10", "255.255.255.0", "192.0.2.1"))
	require.Error(t, validateStaticGateway("192.0.2.10", "255.255.255.0", "198.51.100.1"))
	require.Error(t, validateStaticGateway("192.0.2.10", "255.255.255.0", "192.0.2.0"))
	require.Error(t, validateStaticGateway("192.0.2.10", "255.255.255.0", "192.0.2.255"))
	require.Error(t, validateStaticGateway("192.0.2.10", "255.255.255.0", "192.0.2.10"))
	require.Error(t, validateStaticGateway("192.0.2.10", "255.0.255.0", "192.0.2.1"))
}

func TestNormalizeStaticDNSList(t *testing.T) {
	got, err := normalizeStaticDNSList([]string{"192.0.2.53", " 198.51.100.53 "})
	require.NoError(t, err)
	require.Equal(t, []string{"192.0.2.53", "198.51.100.53"}, got)

	_, err = normalizeStaticDNSList([]string{"192.0.2.53", "192.0.2.53"})
	require.Error(t, err)
	_, err = normalizeStaticDNSList([]string{"192.0.2.53", ""})
	require.Error(t, err)
	_, err = normalizeStaticDNSList([]string{"2001:db8::53"})
	require.Error(t, err)
	_, err = normalizeStaticDNSList([]string{"not-an-ip"})
	require.Error(t, err)
}

func TestValidateStaticVIPAddress(t *testing.T) {
	require.NoError(t, validateStaticVIPAddress("192.0.2.200", "192.0.2.10", "255.255.255.0"))
	require.Error(t, validateStaticVIPAddress("", "192.0.2.10", "255.255.255.0"))
	require.Error(t, validateStaticVIPAddress("192.0.2.10", "192.0.2.10", "255.255.255.0"))
	require.Error(t, validateStaticVIPAddress("198.51.100.20", "192.0.2.10", "255.255.255.0"))
	require.Error(t, validateStaticVIPAddress("192.0.2.0", "192.0.2.10", "255.255.255.0"))
	require.Error(t, validateStaticVIPAddress("192.0.2.255", "192.0.2.10", "255.255.255.0"))
	require.Error(t, validateStaticVIPAddress("2001:db8::20", "192.0.2.10", "255.255.255.0"))
}
