#!/usr/bin/env python3
"""Wire the LayerSentry milestone UX into the pinned Harvester v1.8.2 installer.

The actual progress renderer/output observer lives in
pkg/console/layersentry_install_progress.go.  This transform only wires that
reviewable implementation into the upstream-compatible installer lifecycle.
It is deterministic and idempotent and does not rename upstream APIs/contracts.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UTIL = ROOT / "pkg/console/util.go"
PANELS = ROOT / "pkg/console/install_panels.go"
PROGRESS = ROOT / "pkg/console/layersentry_install_progress.go"


def replace_once_in_region(
    text: str,
    start_anchor: str,
    end_anchor: str,
    old: str,
    new: str,
    label: str,
) -> str:
    """Replace exactly once inside a named source region."""
    start_count = text.count(start_anchor)
    if start_count != 1:
        raise SystemExit(
            f"LayerSentry installer UX transform: expected one {label} region start, "
            f"found {start_count}"
        )
    start = text.index(start_anchor)
    end = text.find(end_anchor, start + len(start_anchor))
    if end < 0:
        raise SystemExit(
            f"LayerSentry installer UX transform: missing {label} region end"
        )
    region = text[start:end]
    if new in region:
        return text
    count = region.count(old)
    if count != 1:
        raise SystemExit(
            f"LayerSentry installer UX transform: expected one {label} anchor in region, "
            f"found {count}"
        )
    region = region.replace(old, new, 1)
    return text[:start] + region + text[end:]


def patch_util() -> None:
    text = UTIL.read_text(encoding="utf-8")

    execute_start = "func execute(ctx context.Context, g *gocui.Gui, env []string, cmdName string) error {\n"
    execute_end = "func dropCR(data []byte) []byte {\n"

    # The dedicated LayerSentry capture function writes every native line to
    # logrus and intentionally does not append those lines to the customer-facing
    # install panel.  It observes real harv-install output for milestone changes.
    old_capture = '''\tvar wg sync.WaitGroup\n\tvar writeLock sync.Mutex\n\n\twg.Add(2)\n\tgo func() {\n\t\tdefer wg.Done()\n\t\tprintToPanelAndLog(g, installPanel, "[stderr]", stderr, &writeLock)\n\t}()\n\n\tgo func() {\n\t\tdefer wg.Done()\n\t\tprintToPanelAndLog(g, installPanel, "[stdout]", stdout, &writeLock)\n\t}()\n'''
    new_capture = '''\tvar wg sync.WaitGroup\n\n\twg.Add(2)\n\tgo func() {\n\t\tdefer wg.Done()\n\t\tcaptureLayerSentryInstallOutput(g, cmdName, "[stderr]", stderr)\n\t}()\n\n\tgo func() {\n\t\tdefer wg.Done()\n\t\tcaptureLayerSentryInstallOutput(g, cmdName, "[stdout]", stdout)\n\t}()\n'''
    text = replace_once_in_region(
        text,
        execute_start,
        execute_end,
        old_capture,
        new_capture,
        "execute output capture",
    )

    do_install_start = "func doInstall(g *gocui.Gui, hvstConfig *config.HarvesterConfig, webhooks RendererWebhooks) error {\n"
    do_install_end = "func doUpgrade(g *gocui.Gui) error {\n"

    old_start = '''func doInstall(g *gocui.Gui, hvstConfig *config.HarvesterConfig, webhooks RendererWebhooks) error {\n\tctx := context.TODO()\n\twebhooks.Handle(EventInstallStarted)\n\n\terr := updateSystemSettings(hvstConfig)\n'''
    new_start = '''func doInstall(g *gocui.Gui, hvstConfig *config.HarvesterConfig, webhooks RendererWebhooks) error {\n\tctx := context.TODO()\n\twebhooks.Handle(EventInstallStarted)\n\tresetLayerSentryInstallProgress()\n\tsetLayerSentryInstallProgress(g, "Validating installation media", 5)\n\tif err := validateLayerSentryInstallMedia(); err != nil {\n\t\twebhooks.Handle(EventInstallFailed)\n\t\treturn err\n\t}\n\n\terr := updateSystemSettings(hvstConfig)\n'''
    text = replace_once_in_region(
        text, do_install_start, do_install_end, old_start, new_start, "install-start lifecycle"
    )

    old_disks = '''\tif hvstConfig.ShouldCreateDataPartitionOnOsDisk() {\n'''
    new_disks = '''\tsetLayerSentryInstallProgress(g, "Preparing system disks", 18)\n\tif hvstConfig.ShouldCreateDataPartitionOnOsDisk() {\n'''
    text = replace_once_in_region(
        text, do_install_start, do_install_end, old_disks, new_disks, "disk-preparation lifecycle"
    )

    old_install = '''\tif err := execute(ctx, g, env, "/usr/sbin/harv-install"); err != nil {\n'''
    new_install = '''\tsetLayerSentryInstallProgress(g, "Installing base operating system", 32)\n\tif err := execute(ctx, g, env, "/usr/sbin/harv-install"); err != nil {\n'''
    text = replace_once_in_region(
        text, do_install_start, do_install_end, old_install, new_install, "native installer execution"
    )

    old_success = '''\t}\n\twebhooks.Handle(EventInstallSuceeded)\n\n\t// Enable CTRL-C to stop system from rebooting after installation\n'''
    new_success = '''\t}\n\tsetLayerSentryInstallProgress(g, "Applying LayerSentry branding and defaults", 88)\n\twebhooks.Handle(EventInstallSuceeded)\n\n\t// Enable CTRL-C to stop system from rebooting after installation\n'''
    text = replace_once_in_region(
        text, do_install_start, do_install_end, old_success, new_success, "native-install success lifecycle"
    )

    old_shutdown = '''\tif err := execute(cancellableCtx, g, env, "/usr/sbin/cos-installer-shutdown"); err != nil {\n'''
    new_shutdown = '''\tsetLayerSentryInstallProgress(g, "Finalizing installation", 96)\n\tif err := execute(cancellableCtx, g, env, "/usr/sbin/cos-installer-shutdown"); err != nil {\n'''
    text = replace_once_in_region(
        text, do_install_start, do_install_end, old_shutdown, new_shutdown, "finalization lifecycle"
    )

    old_complete = '''\tif err := execute(cancellableCtx, g, env, "/usr/sbin/cos-installer-shutdown"); err != nil {\n\t\twebhooks.Handle(EventInstallFailed)\n\t\treturn err\n\t}\n\n\treturn nil\n}\n'''
    new_complete = '''\tif err := execute(cancellableCtx, g, env, "/usr/sbin/cos-installer-shutdown"); err != nil {\n\t\twebhooks.Handle(EventInstallFailed)\n\t\treturn err\n\t}\n\tsetLayerSentryInstallProgress(g, "LayerSentry installation completed", 100)\n\n\treturn nil\n}\n'''
    text = replace_once_in_region(
        text, do_install_start, do_install_end, old_complete, new_complete, "installation completion lifecycle"
    )

    UTIL.write_text(text, encoding="utf-8")


def patch_panels() -> None:
    text = PANELS.read_text(encoding="utf-8")
    panel_start = "func addInstallPanel(c *Console) error {\n"
    panel_end = "func addSpinnerPanel(c *Console) error {\n"

    old_panel_start = '''\tinstallV := widgets.NewPanel(c.Gui, installPanel)\n\tinstallV.PreShow = func() error {\n'''
    new_panel_start = '''\tinstallV := widgets.NewPanel(c.Gui, installPanel)\n\tinstallV.SetContent(renderLayerSentryInstallProgress("Validating installation media", 0))\n\tinstallV.PreShow = func() error {\n'''
    text = replace_once_in_region(
        text, panel_start, panel_end, old_panel_start, new_panel_start, "install-panel initial content"
    )

    old_scroll = '''\tinstallV.Wrap = true\n\tinstallV.Autoscroll = true\n'''
    new_scroll = '''\tinstallV.Wrap = true\n\tinstallV.Autoscroll = false\n'''
    text = replace_once_in_region(
        text, panel_start, panel_end, old_scroll, new_scroll, "install-panel scrolling"
    )

    PANELS.write_text(text, encoding="utf-8")


def validate_result() -> None:
    util = UTIL.read_text(encoding="utf-8")
    panels = PANELS.read_text(encoding="utf-8")
    progress = PROGRESS.read_text(encoding="utf-8")

    # The implementation must exist once, in the dedicated source file.
    progress_markers = (
        "func resetLayerSentryInstallProgress()",
        "func renderLayerSentryInstallProgress(stage string, percent int) string",
        "func setLayerSentryInstallProgress(g *gocui.Gui, stage string, percent int)",
        "func validateLayerSentryInstallMedia() error",
        "func captureLayerSentryInstallOutput(g *gocui.Gui, commandName, logPrefix string, reader io.Reader)",
        "func observeLayerSentryInstallMilestone(g *gocui.Gui, line string)",
        'logrus.Infof("%s: %s", logPrefix, line)',
        '"Installing LayerSentry packages"',
        '"Configuring Kubernetes and platform services"',
        '"Configuring networking and storage"',
    )
    for marker in progress_markers:
        if marker not in progress:
            raise SystemExit(f"LayerSentry progress implementation missing marker: {marker}")

    if "func captureLayerSentryInstallOutput(" in util:
        raise SystemExit("LayerSentry progress helpers must not be duplicated in util.go")

    required_util = (
        'captureLayerSentryInstallOutput(g, cmdName, "[stderr]", stderr)',
        'captureLayerSentryInstallOutput(g, cmdName, "[stdout]", stdout)',
        'setLayerSentryInstallProgress(g, "Validating installation media", 5)',
        'setLayerSentryInstallProgress(g, "Preparing system disks", 18)',
        'setLayerSentryInstallProgress(g, "Installing base operating system", 32)',
        'setLayerSentryInstallProgress(g, "Applying LayerSentry branding and defaults", 88)',
        'setLayerSentryInstallProgress(g, "Finalizing installation", 96)',
        'setLayerSentryInstallProgress(g, "LayerSentry installation completed", 100)',
    )
    for marker in required_util:
        if marker not in util:
            raise SystemExit(f"LayerSentry installer lifecycle missing marker: {marker}")

    if 'installV.SetContent(renderLayerSentryInstallProgress("Validating installation media", 0))' not in panels:
        raise SystemExit("LayerSentry installer UX transform did not seed the install panel")
    if "installV.Autoscroll = false" not in panels:
        raise SystemExit("LayerSentry installer UX transform did not disable raw-output scrolling")

    execute_start = util.index(
        "func execute(ctx context.Context, g *gocui.Gui, env []string, cmdName string) error {\n"
    )
    execute_end = util.index("func dropCR(data []byte) []byte {\n", execute_start)
    execute_region = util[execute_start:execute_end]
    if "printToPanelAndLog(g, installPanel" in execute_region:
        raise SystemExit("raw command output is still copied directly to the main installation panel")
    if "var writeLock sync.Mutex" in execute_region:
        raise SystemExit("obsolete execute output lock remains after LayerSentry capture wiring")


if __name__ == "__main__":
    if not PROGRESS.is_file():
        raise SystemExit("LayerSentry progress implementation file is missing")
    patch_util()
    patch_panels()
    validate_result()
    print("LAYERSENTRY INSTALLER MILESTONE UX TRANSFORM: PASS")
