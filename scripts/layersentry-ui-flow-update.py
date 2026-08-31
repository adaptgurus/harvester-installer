from pathlib import Path


PATH = Path("pkg/console/install_panels.go")
text = PATH.read_text()


def replace_idempotent(old: str, new: str, label: str) -> None:
    global text
    if new in text:
        return
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one source marker, found {count}")
    text = text.replace(old, new, 1)


def replace_in_function(start_marker: str, end_marker: str, old: str, new: str, label: str) -> None:
    global text
    start = text.index(start_marker)
    end = text.index(end_marker, start)
    block = text[start:end]
    if new in block:
        return
    count = block.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one source marker in function block, found {count}")
    block = block.replace(old, new, 1)
    text = text[:start] + block + text[end:]


# LayerSentry interactive installer defaults to a vendor-neutral, globally
# reachable NTP endpoint instead of the SUSE pool used by upstream Harvester.
replace_idempotent(
    'NTPServers: "0.suse.pool.ntp.org",',
    'NTPServers: "time.google.com",',
    "NTP default",
)

# Keep proxy configuration in the interactive flow, but hide the optional SSH
# key URL/password-auth page and optional remote config URL page. Their backend
# implementations remain intact for automatic/config-driven installation.
replace_in_function(
    "func addProxyPanel",
    "func addCloudInitPanel",
    'return showNext(c, sshKeyPanel)',
    'return showNext(c, confirmInstallPanel)',
    "proxy-to-confirm navigation",
)

# The confirmation page must navigate back to the last visible interactive page
# rather than exposing the hidden remote-config page on Escape.
replace_in_function(
    "func addConfirmInstallPanel",
    "func addConfirmUpgradePanel",
    '''\t\t\tif installModeOnly {
\t\t\t\treturn showDiskPage(c)
\t\t\t}
\t\t\treturn showNext(c, cloudInitPanel)
''',
    '''\t\t\tif installModeOnly {
\t\t\t\treturn showDiskPage(c)
\t\t\t}
\t\t\treturn showNext(c, proxyPanel)
''',
    "confirm-to-proxy navigation",
)

# Explain the purpose of the VIP on the actual VIP entry page. The existing red
# vipTextPanel remains reserved for validation/conflict errors.
replace_idempotent(
    '''\t\tvipV.Value = c.config.Vip
\t\tvipTextV.SetContent("")
\t\treturn c.setContentByName(titlePanel, vipTitle)
''',
    '''\t\tvipV.Value = c.config.Vip
\t\tvipTextV.SetContent("")
\t\tif err := c.setContentByName(notePanel, "VIP (Virtual IP) provides one stable management endpoint for the LayerSentry cluster. Use an unused IP in the same subnet as the management nodes. The VIP enables high availability and failover so the UI/API remains reachable if a node fails."); err != nil {
\t\t\treturn err
\t\t}
\t\treturn c.setContentByName(titlePanel, vipTitle)
''',
    "VIP help text",
)

PATH.write_text(text)

# Strong postconditions scoped to the visible interactive flow.
final = PATH.read_text()
if 'NTPServers: "time.google.com",' not in final:
    raise SystemExit("LayerSentry NTP default was not applied")
if 'VIP (Virtual IP) provides one stable management endpoint for the LayerSentry cluster.' not in final:
    raise SystemExit("LayerSentry VIP explanation was not applied")

proxy_start = final.index("func addProxyPanel")
cloud_start = final.index("func addCloudInitPanel")
proxy_block = final[proxy_start:cloud_start]
if "showNext(c, sshKeyPanel)" in proxy_block:
    raise SystemExit("SSH screen is still reachable from the interactive proxy page")
if "showNext(c, confirmInstallPanel)" not in proxy_block:
    raise SystemExit("interactive proxy page does not advance directly to confirmation")

confirm_start = final.index("func addConfirmInstallPanel")
confirm_end = final.index("func addConfirmUpgradePanel")
confirm_block = final[confirm_start:confirm_end]
if "showNext(c, cloudInitPanel)" in confirm_block:
    raise SystemExit("remote LayerSentry config screen is still reachable from confirmation")
if "showNext(c, proxyPanel)" not in confirm_block:
    raise SystemExit("confirmation page does not return to the visible proxy page")
