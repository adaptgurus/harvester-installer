#!/usr/bin/env python3
"""Apply the LayerSentry installer progress UX to the upstream-compatible Go sources.

The transform is deterministic, idempotent, and committed as a build input so the ISO
remains source/provenance-bound without renaming upstream internal contracts.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UTIL = ROOT / "pkg/console/util.go"
PANELS = ROOT / "pkg/console/install_panels.go"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if new in text:
        return text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"LayerSentry installer UX transform: expected one {label} anchor, found {count}")
    return text.replace(old, new, 1)


def patch_util() -> None:
    text = UTIL.read_text(encoding="utf-8")

    old_capture = '''\twg.Add(2)\n\tgo func() {\n\t\tdefer wg.Done()\n\t\tprintToPanelAndLog(g, installPanel, "[stderr]", stderr, &writeLock)\n\t}()\n\n\tgo func() {\n\t\tdefer wg.Done()\n\t\tprintToPanelAndLog(g, installPanel, "[stdout]", stdout, &writeLock)\n\t}()\n'''
    new_capture = '''\twg.Add(2)\n\tgo func() {\n\t\tdefer wg.Done()\n\t\tcaptureLayerSentryInstallOutput(g, cmdName, "[stderr]", stderr)\n\t}()\n\n\tgo func() {\n\t\tdefer wg.Done()\n\t\tcaptureLayerSentryInstallOutput(g, cmdName, "[stdout]", stdout)\n\t}()\n'''
    text = replace_once(text, old_capture, new_capture, "execute output capture")

    old_start = '''func doInstall(g *gocui.Gui, hvstConfig *config.HarvesterConfig, webhooks RendererWebhooks) error {\n\tctx := context.TODO()\n\twebhooks.Handle(EventInstallStarted)\n\n\terr := updateSystemSettings(hvstConfig)\n'''
    new_start = '''func doInstall(g *gocui.Gui, hvstConfig *config.HarvesterConfig, webhooks RendererWebhooks) error {\n\tctx := context.TODO()\n\twebhooks.Handle(EventInstallStarted)\n\tresetLayerSentryInstallProgress()\n\tsetLayerSentryInstallProgress(g, "Validating installation media", 5)\n\tif err := validateLayerSentryInstallMedia(); err != nil {\n\t\twebhooks.Handle(EventInstallFailed)\n\t\treturn err\n\t}\n\n\terr := updateSystemSettings(hvstConfig)\n'''
    text = replace_once(text, old_start, new_start, "install-start lifecycle")

    old_disks = '''\tif hvstConfig.ShouldCreateDataPartitionOnOsDisk() {\n'''
    new_disks = '''\tsetLayerSentryInstallProgress(g, "Preparing system disks", 18)\n\tif hvstConfig.ShouldCreateDataPartitionOnOsDisk() {\n'''
    text = replace_once(text, old_disks, new_disks, "disk-preparation lifecycle")

    old_install = '''\tif err := execute(ctx, g, env, "/usr/sbin/harv-install"); err != nil {\n'''
    new_install = '''\tsetLayerSentryInstallProgress(g, "Installing base operating system", 32)\n\tif err := execute(ctx, g, env, "/usr/sbin/harv-install"); err != nil {\n'''
    text = replace_once(text, old_install, new_install, "native installer execution")

    old_success = '''\t}\n\twebhooks.Handle(EventInstallSuceeded)\n\n\t// Enable CTRL-C to stop system from rebooting after installation\n'''
    new_success = '''\t}\n\tsetLayerSentryInstallProgress(g, "Finalizing installation", 96)\n\tsetLayerSentryInstallProgress(g, "LayerSentry installation completed", 100)\n\twebhooks.Handle(EventInstallSuceeded)\n\n\t// Enable CTRL-C to stop system from rebooting after installation\n'''
    text = replace_once(text, old_success, new_success, "install-success lifecycle")

    UTIL.write_text(text, encoding="utf-8")


def patch_panels() -> None:
    text = PANELS.read_text(encoding="utf-8")

    old_content = '''\t\tContent: layersentryMultilineBanner(\n\t\t\t"Installing LayerSentry",\n\t\t\t"Installation output follows. Do not power off the system.",\n\t\t),\n'''
    new_content = '''\t\tContent: renderLayerSentryInstallProgress("Validating installation media", 0),\n'''
    text = replace_once(text, old_content, new_content, "install-panel content")

    old_view = '''\tview.Title = fmt.Sprintf(" %s | Full-Offline Installation ", layersentryTitle)\n\tview.Autoscroll = true\n\tview.Wrap = true\n'''
    new_view = '''\tview.Title = fmt.Sprintf(" %s | Full-Offline Installation ", layersentryTitle)\n\tview.Autoscroll = false\n\tview.Wrap = true\n'''
    text = replace_once(text, old_view, new_view, "install-panel scrolling")

    PANELS.write_text(text, encoding="utf-8")


def validate_result() -> None:
    util = UTIL.read_text(encoding="utf-8")
    panels = PANELS.read_text(encoding="utf-8")
    required = (
        "captureLayerSentryInstallOutput(g, cmdName",
        'setLayerSentryInstallProgress(g, "Validating installation media", 5)',
        'setLayerSentryInstallProgress(g, "Preparing system disks", 18)',
        'setLayerSentryInstallProgress(g, "Installing base operating system", 32)',
        'setLayerSentryInstallProgress(g, "LayerSentry installation completed", 100)',
    )
    for marker in required:
        if marker not in util:
            raise SystemExit(f"LayerSentry installer UX transform missing marker: {marker}")
    if 'renderLayerSentryInstallProgress("Validating installation media", 0)' not in panels:
        raise SystemExit("LayerSentry installer UX transform did not replace the install panel")
    if "Installation output follows. Do not power off the system." in panels:
        raise SystemExit("raw-output install panel copy remains after LayerSentry transform")


if __name__ == "__main__":
    patch_util()
    patch_panels()
    validate_result()
    print("LAYERSENTRY INSTALLER MILESTONE UX TRANSFORM: PASS")
