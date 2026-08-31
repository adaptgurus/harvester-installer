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
replace_idempotent(
    'return showNext(c, sshKeyPanel)',
    'return showNext(c, confirmInstallPanel)',
    "proxy-to-confirm navigation",
)

# The confirmation page must navigate back to the last visible interactive page
# rather than exposing the hidden remote-config page on Escape.
replace_idempotent(
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

# Strong postconditions: fail loudly if a future upstream change makes this
# patch ambiguous or reintroduces the hidden interactive pages.
final = PATH.read_text()
required = [
    'NTPServers: "time.google.com",',
    'return showNext(c, confirmInstallPanel)',
    'return showNext(c, proxyPanel)',
    'VIP (Virtual IP) provides one stable management endpoint for the LayerSentry cluster.',
]
for marker in required:
    if marker not in final:
        raise SystemExit(f"missing required LayerSentry flow marker: {marker}")
