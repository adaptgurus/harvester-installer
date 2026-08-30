from pathlib import Path
import re


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one match, found {count}: {old[:100]!r}")
    p.write_text(text.replace(old, new, 1))


def sub_once(path: str, pattern: str, repl: str) -> None:
    p = Path(path)
    text = p.read_text()
    updated, count = re.subn(pattern, repl, text, count=1, flags=re.S)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one regex match for {pattern!r}, found {count}")
    p.write_text(updated)


# Network help: existing DropDown binds Tab to open options; Select multi mode binds Space.
replace_once(
    "pkg/console/constant.go",
    'bondNote               = "Note: Select one or more NICs for the Management NIC.\\nUse the default value for the Bond Mode if only one NIC is selected."',
    'bondNote               = "Note: Press Tab on Management NIC to open the interface list; use Space to select NICs and Enter to confirm.\\nUse the default value for the Bond Mode if only one NIC is selected."',
)

# Interactive install modes: exactly Create/Join. Backend ModeInstall logic stays untouched.
sub_once(
    "pkg/console/install_panels.go",
    r'func addAskCreatePanel\(c \*Console\) error \{\n\ttaskOptionsFunc := func\(\) \(\[\]widgets\.Option, error\) \{.*?\n\t\}\n\t// new cluster or join existing cluster',
    'func addAskCreatePanel(c *Console) error {\n\ttaskOptionsFunc := interactiveInstallModeOptions\n\t// new cluster or join existing cluster',
)
replace_once(
    "pkg/console/install_panels.go",
    '\t\taskCreateV.Value = c.config.Install.Mode\n',
    '\t\tif c.config.Install.Mode == config.ModeCreate || c.config.Install.Mode == config.ModeJoin {\n\t\t\taskCreateV.Value = c.config.Install.Mode\n\t\t} else {\n\t\t\taskCreateV.Value = ""\n\t\t}\n',
)
replace_once(
    "pkg/console/install_panels.go",
    'return c.setContentByName(titlePanel, "Harvester already installed. Choose configuration mode")',
    'return c.setContentByName(titlePanel, fmt.Sprintf("%s already installed. Choose configuration mode", version.ProductName))',
)

# Interactive management network is static-only. DHCP backend code remains for automatic/PXE paths.
sub_once(
    "pkg/console/install_panels.go",
    r'func showNetworkPage\(c \*Console\) error \{.*?\n\}',
    'func showNetworkPage(c *Console) error {\n\tmgmtNetwork.Method = config.NetworkMethodStatic\n\treturn showNext(c, interactiveNetworkPanels()...)\n}',
)
replace_once(
    "pkg/console/install_panels.go",
    '\t\tifaces := askInterfaceV.GetMultiData()\n\t\tif len(ifaces) == 0 {\n\t\t\treturn "Must select at least one interface", nil\n\t\t}\n',
    '\t\tifaces := askInterfaceV.GetMultiData()\n\t\tif err := validateManagementInterfaceSelection(ifaces); err != nil {\n\t\t\treturn err.Error(), nil\n\t\t}\n',
)
sub_once(
    "pkg/console/install_panels.go",
    r'\taskBondModeVConfirm := func\(_ \*gocui\.Gui, _ \*gocui\.View\) error \{\n\t\tmode, err := askBondModeV\.GetData\(\).*?\n\t\}\n\taskBondModeV\.KeyBindings',
    '''\taskBondModeVConfirm := func(_ *gocui.Gui, _ *gocui.View) error {
\t\tmode, err := askBondModeV.GetData()
\t\tif err != nil {
\t\t\treturn err
\t\t}
\t\tmgmtNetwork.BondOptions = map[string]string{
\t\t\t"mode":   mode,
\t\t\t"miimon": "100",
\t\t}
\t\tmgmtNetwork.Method = config.NetworkMethodStatic
\t\tif err := showBondNote(); err != nil {
\t\t\treturn err
\t\t}
\t\treturn showNext(c, mtuPanel, gatewayPanel, addrMaskPanel, addressPanel)
\t}
\taskBondModeV.KeyBindings''',
)
replace_once(
    "pkg/console/install_panels.go",
    '\t\tgocui.KeyArrowUp: gotoNextPanel(c, []string{askNetworkMethodPanel}, func() (string, error) {\n\t\t\tuserInputData.Address, err = addressV.GetData()\n\t\t\treturn "", err\n\t\t}),',
    '\t\tgocui.KeyArrowUp: gotoNextPanel(c, []string{askBondModePanel}, func() (string, error) {\n\t\t\tuserInputData.Address, err = addressV.GetData()\n\t\t\treturn "", err\n\t\t}),',
)
replace_once(
    "pkg/console/install_panels.go",
    '''\t\tip, ipNet, err := net.ParseCIDR(address)
\t\tif err != nil {
\t\t\t// It's not a CIDR address, but it might be a non-CIDR address
\t\t\tip = net.ParseIP(address)
\t\t\tif ip == nil {
\t\t\t\treturn fmt.Sprintf("%s is not a valid IP address", address), nil
\t\t\t}
\t\t}
''',
    '''\t\tip, ipNet, err := parseStaticIPv4Address(address)
\t\tif err != nil {
\t\t\treturn err.Error(), nil
\t\t}
''',
)
replace_once(
    "pkg/console/install_panels.go",
    '''\t\tif err = checkIP(gateway); err != nil {
\t\t\treturn err.Error(), nil
\t\t}
\t\tmgmtNetwork.Gateway = gateway
''',
    '''\t\tif err = validateStaticGateway(mgmtNetwork.IP, mgmtNetwork.SubnetMask, gateway); err != nil {
\t\t\treturn err.Error(), nil
\t\t}
\t\tmgmtNetwork.Gateway = gateway
''',
)
replace_once(
    "pkg/console/install_panels.go",
    '''\t\t\t\t\tdnsServerList := strings.Split(dnsServers, ",")
\t\t\t\t\tif err = checkIPList(dnsServerList); err != nil {
\t\t\t\t\t\tgotoSpinnerErrorPage(g, spinner, err.Error())
\t\t\t\t\t\treturn
\t\t\t\t\t}
''',
    '''\t\t\t\t\tdnsServerList := strings.Split(dnsServers, ",")
\t\t\t\t\tdnsServerList, err = normalizeStaticDNSList(dnsServerList)
\t\t\t\t\tif err != nil {
\t\t\t\t\t\tgotoSpinnerErrorPage(g, spinner, err.Error())
\t\t\t\t\t\treturn
\t\t\t\t\t}
''',
)

# Static-only VIP page: no mode selector, no editable MAC. A bounded neighbor-table
# probe is performed asynchronously and an already-used VIP is rejected with its MAC.
sub_once(
    "pkg/console/install_panels.go",
    r'func addVIPPanel\(c \*Console\) error \{.*?\n\}\n\nfunc addNTPServersPanel',
    '''func addVIPPanel(c *Console) error {
\tsetLocation := createVerticalLocator(c)

\tvipV, err := widgets.NewInput(c.Gui, vipPanel, vipLabel, false)
\tif err != nil {
\t\treturn err
\t}
\tvipTextV := widgets.NewPanel(c.Gui, vipTextPanel)

\tcloseThisPage := func() {
\t\tc.CloseElements(vipPanel, vipTextPanel)
\t}
\tgotoPrevPage := func(_ *gocui.Gui, _ *gocui.View) error {
\t\tcloseThisPage()
\t\treturn showNext(c, dnsServersPanel)
\t}
\tgotoNextPage := func(_ *gocui.Gui, _ *gocui.View) error {
\t\tcloseThisPage()
\t\treturn showNext(c, tokenPanel)
\t}
\tgotoVerifyIP := func(g *gocui.Gui, v *gocui.View) error {
\t\tvip, err := vipV.GetData()
\t\tif err != nil {
\t\t\treturn err
\t\t}
\t\tif err := validateStaticVIPAddress(vip, mgmtNetwork.IP, mgmtNetwork.SubnetMask); err != nil {
\t\t\tvipTextV.SetContent(err.Error())
\t\t\treturn nil
\t\t}

\t\tvipTextV.SetContent("")
\t\tspinner := NewSpinner(c.Gui, vipTextPanel, "Checking VIP availability...")
\t\tspinner.Start()
\t\tgo func(g *gocui.Gui) {
\t\t\tmac, probeErr := probeIPv4NeighborMAC(
\t\t\t\tgetManagementInterfaceName(c.config.ManagementInterface),
\t\t\t\tvip,
\t\t\t\tvipNeighborProbeTimeout,
\t\t\t)
\t\t\tif probeErr != nil {
\t\t\t\tspinner.Stop(true, fmt.Sprintf("Unable to verify VIP availability: %v", probeErr))
\t\t\t\tg.Update(func(_ *gocui.Gui) error {
\t\t\t\t\treturn showNext(c, vipPanel)
\t\t\t\t})
\t\t\t\treturn
\t\t\t}
\t\t\tif len(mac) != 0 {
\t\t\t\tspinner.Stop(true, fmt.Sprintf("VIP %s is already in use by MAC %s", vip, mac.String()))
\t\t\t\tg.Update(func(_ *gocui.Gui) error {
\t\t\t\t\treturn showNext(c, vipPanel)
\t\t\t\t})
\t\t\t\treturn
\t\t\t}

\t\t\tspinner.Stop(false, "")
\t\t\tc.config.Vip = vip
\t\t\tc.config.VipMode = config.NetworkMethodStatic
\t\t\tc.config.VipHwAddr = ""
\t\t\tg.Update(func(_ *gocui.Gui) error {
\t\t\t\treturn gotoNextPage(g, v)
\t\t\t})
\t\t}(c.Gui)
\t\treturn nil
\t}

\tvipV.KeyBindings = map[gocui.Key]func(*gocui.Gui, *gocui.View) error{
\t\tgocui.KeyArrowUp:   gotoPrevPage,
\t\tgocui.KeyArrowDown: gotoVerifyIP,
\t\tgocui.KeyEnter:     gotoVerifyIP,
\t\tgocui.KeyEsc:       gotoPrevPage,
\t}
\tvipV.PreShow = func() error {
\t\tc.Gui.Cursor = true
\t\tc.config.VipMode = config.NetworkMethodStatic
\t\tc.config.VipHwAddr = ""
\t\tvipV.Value = c.config.Vip
\t\tvipTextV.SetContent("")
\t\treturn c.setContentByName(titlePanel, vipTitle)
\t}

\tsetLocation(vipV, 3)
\tc.AddElement(vipPanel, vipV)

\tvipTextV.FgColor = gocui.ColorRed
\tvipTextV.Focus = false
\tvipTextV.Wrap = true
\tsetLocation(vipTextV, 3)
\tc.AddElement(vipTextPanel, vipTextV)

\treturn nil
}

func addNTPServersPanel''',
)
replace_once(
    "pkg/console/install_panels.go",
    'return showNext(c, vipTextPanel, askVipMethodPanel)',
    'return showNext(c, interactiveVIPPanels()...)',
)
text = Path("pkg/console/install_panels.go").read_text()
if 'showNext(c, vipTextPanel, askVipMethodPanel)' in text:
    text = text.replace('showNext(c, vipTextPanel, askVipMethodPanel)', 'showNext(c, interactiveVIPPanels()...)')
    Path("pkg/console/install_panels.go").write_text(text)

# User-facing installer branding. Internal compatibility identifiers/logs remain unchanged.
replacements = {
    'diskFatalV.SetContent("No disk detected. Harvester requires at least one disk.")': 'diskFatalV.SetContent(fmt.Sprintf("No disk detected. %s requires at least one disk.", version.ProductName))',
    'wipeDisksTitlePanelV.SetContent("Additional Harvester installations detected")': 'wipeDisksTitlePanelV.SetContent(fmt.Sprintf("Additional %s installations detected", version.ProductName))',
    'return c.setContentByName(titlePanel, "Optional: remote Harvester config")': 'return c.setContentByName(titlePanel, fmt.Sprintf("Optional: remote %s config", version.ProductName))',
    'return c.setContentByName(titlePanel, fmt.Sprintf("Confirm upgrading Harvester to %s?", version.Version))': 'return c.setContentByName(titlePanel, fmt.Sprintf("Confirm upgrading %s to %s?", version.ProductName, version.Version))',
    'installV.Title = " Installing Harvester "': 'installV.Title = fmt.Sprintf(" Installing %s ", version.ProductName)',
    'upgradeV.Title = " Upgrading Harvester "': 'upgradeV.Title = fmt.Sprintf(" Upgrading %s ", version.ProductName)',
}
for old, new in replacements.items():
    replace_once("pkg/console/install_panels.go", old, new)

replace_once(
    "pkg/console/install_panels.go",
    'confirmV.SetContent(options +\n\t\t\t\t\t"\\nHarvester is already installed. It will be configured with the above configuration. Continue?\\n")',
    'confirmV.SetContent(options + fmt.Sprintf("\\n%s is already installed. It will be configured with the above configuration. Continue?\\n", version.ProductName))',
)
replace_once(
    "pkg/console/install_panels.go",
    'confirmV.SetContent(options +\n\t\t\t\t\t"\\nHarvester will be copied to local disk. No configuration will be performed. Continue?\\n")',
    'confirmV.SetContent(options + fmt.Sprintf("\\n%s will be copied to local disk. No configuration will be performed. Continue?\\n", version.ProductName))',
)
replace_once(
    "pkg/console/install_panels.go",
    'confirmV.SetContent(options +\n\t\t\t\t\t"\\nYour disk will be formatted and Harvester will be installed with the above configuration. Continue?\\n")',
    'confirmV.SetContent(options + fmt.Sprintf("\\nYour disk will be formatted and %s will be installed with the above configuration. Continue?\\n", version.ProductName))',
)

# Final console/dashboard branding and display version.
replace_once(
    "pkg/console/dashboard_panels.go",
    'statusSettingUpHarv = "Setting up Harvester"',
    'statusSettingUpHarv = "Setting up LayerSentry"',
)
sub_once(
    "pkg/console/dashboard_panels.go",
    r'\tlogo string = `.*?`\n',
    '''\tlogo string = `
+------------------------------------------------------------------------+
|                              LAYERSENTRY                                |
+------------------------------------------------------------------------+`
''',
)
replace_once(
    "pkg/console/dashboard_panels.go",
    'v.Title = " Harvester Cluster "',
    'v.Title = fmt.Sprintf(" %s Cluster ", version.ProductName)',
)
replace_once(
    "pkg/console/dashboard_panels.go",
    'fmt.Fprintf(v, "<Use F12 to switch between Harvester console and Shell>")',
    'fmt.Fprintf(v, "<Use F12 to switch between %s console and Shell>", version.ProductName)',
)
replace_once(
    "pkg/console/dashboard_panels.go",
    'versionStr := "version: " + version.HarvesterVersion',
    'versionStr := "version: " + version.ProductVersion',
)

# Boot-visible OS name is LayerSentry while release metadata keeps the underlying Harvester base version.
replace_once(
    "scripts/package-harvester-os",
    'PRETTY_NAME="Harvester ${VERSION}"\n\ncat > harvester-release.yaml <<EOF',
    'PRETTY_NAME="LayerSentry 1.0"\nBASE_OS_RELEASE_NAME="Harvester ${VERSION}"\n\ncat > harvester-release.yaml <<EOF',
)
replace_once(
    "scripts/package-harvester-os",
    'os: ${PRETTY_NAME}',
    'os: ${BASE_OS_RELEASE_NAME}',
)

print("LayerSentry source transformation applied successfully")
