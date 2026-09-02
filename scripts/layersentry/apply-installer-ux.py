#!/usr/bin/env python3
"""Apply the LayerSentry installer progress UX to the upstream-compatible Go sources.

The transform is deterministic, idempotent, and committed as a build input so the ISO
remains source/provenance-bound without renaming upstream internal contracts.

Customer-facing behavior:
- native harv-install stdout/stderr is preserved in logrus/install logs;
- package names and other raw harv-install lines are not copied into the main panel;
- progress advances only on real installer lifecycle/output events (never timers);
- non-harv-install command output keeps the upstream panel behavior.
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
        raise SystemExit(
            f"LayerSentry installer UX transform: expected one {label} anchor, found {count}"
        )
    return text.replace(old, new, 1)


def replace_once_in_region(
    text: str,
    start_anchor: str,
    end_anchor: str,
    old: str,
    new: str,
    label: str,
) -> str:
    """Replace exactly once inside a named source region, ignoring similar code elsewhere."""
    if text.count(start_anchor) != 1:
        raise SystemExit(
            f"LayerSentry installer UX transform: expected one {label} region start, "
            f"found {text.count(start_anchor)}"
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


def insert_before_once(text: str, anchor: str, block: str, marker: str, label: str) -> str:
    if marker in text:
        return text
    count = text.count(anchor)
    if count != 1:
        raise SystemExit(
            f"LayerSentry installer UX transform: expected one {label} anchor, found {count}"
        )
    return text.replace(anchor, block + anchor, 1)


def patch_util() -> None:
    text = UTIL.read_text(encoding="utf-8")

    execute_start = "func execute(ctx context.Context, g *gocui.Gui, env []string, cmdName string) error {\n"
    execute_end = "func dropCR(data []byte) []byte {\n"
    old_capture = '''\twg.Add(2)\n\tgo func() {\n\t\tdefer wg.Done()\n\t\tprintToPanelAndLog(g, installPanel, "[stderr]", stderr, &writeLock)\n\t}()\n\n\tgo func() {\n\t\tdefer wg.Done()\n\t\tprintToPanelAndLog(g, installPanel, "[stdout]", stdout, &writeLock)\n\t}()\n'''
    new_capture = '''\twg.Add(2)\n\tgo func() {\n\t\tdefer wg.Done()\n\t\tcaptureLayerSentryInstallOutput(g, cmdName, installPanel, "[stderr]", stderr, &writeLock)\n\t}()\n\n\tgo func() {\n\t\tdefer wg.Done()\n\t\tcaptureLayerSentryInstallOutput(g, cmdName, installPanel, "[stdout]", stdout, &writeLock)\n\t}()\n'''
    text = replace_once_in_region(
        text,
        execute_start,
        execute_end,
        old_capture,
        new_capture,
        "execute output capture",
    )

    helper_anchor = "func saveElementalConfig(obj interface{}) (string, string, error) {\n"
    helper_marker = "func captureLayerSentryInstallOutput("
    helper_block = r'''// LayerSentry installer progress UX. These values are driven by real installer
// lifecycle/output events. There is intentionally no timer-based progress.
const layersentryNativeInstaller = "/usr/sbin/harv-install"

var layersentryInstallProgress = struct {
	sync.Mutex
	percent int
	stage   string
}{}

func resetLayerSentryInstallProgress() {
	layersentryInstallProgress.Lock()
	layersentryInstallProgress.percent = 0
	layersentryInstallProgress.stage = ""
	layersentryInstallProgress.Unlock()
}

func renderLayerSentryInstallProgress(stage string, percent int) string {
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	const width = 32
	filled := percent * width / 100
	return fmt.Sprintf(
		"                 LAYERSENTRY\n"+
			"                    v1.0\n\n"+
			"             Installing LayerSentry\n\n"+
			"Stage: %s\n\n"+
			"[%s%s] %d%%\n\n"+
			"Please wait. Do not power off the system.\n",
		stage,
		strings.Repeat("#", filled),
		strings.Repeat("-", width-filled),
		percent,
	)
}

func setLayerSentryInstallProgress(g *gocui.Gui, stage string, percent int) {
	layersentryInstallProgress.Lock()
	if percent < layersentryInstallProgress.percent ||
		(percent == layersentryInstallProgress.percent && stage == layersentryInstallProgress.stage) {
		layersentryInstallProgress.Unlock()
		return
	}
	layersentryInstallProgress.percent = percent
	layersentryInstallProgress.stage = stage
	layersentryInstallProgress.Unlock()

	content := renderLayerSentryInstallProgress(stage, percent)
	done := make(chan struct{})
	g.Update(func(g *gocui.Gui) error {
		defer close(done)
		v, err := g.View(installPanel)
		if err != nil {
			return err
		}
		v.Clear()
		_, err = fmt.Fprint(v, content)
		return err
	})
	<-done
}

func validateLayerSentryInstallMedia() error {
	required := []string{
		layersentryNativeInstaller,
		"/etc/harvester-release.yaml",
		"/usr/local/sbin/layersentry-branding.sh",
		"/etc/systemd/system/layersentry-branding.service",
	}
	for _, path := range required {
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("LayerSentry installation media validation failed for %s: %w", path, err)
		}
		if info.IsDir() {
			return fmt.Errorf("LayerSentry installation media validation failed: %s is not a file", path)
		}
	}
	return nil
}

func updateLayerSentryInstallProgressFromOutput(g *gocui.Gui, line string) {
	// The arrival of native installer output is itself a real milestone: the
	// installation engine is actively processing the offline payload.
	setLayerSentryInstallProgress(g, "Installing LayerSentry packages", 48)

	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "kubernetes"),
		strings.Contains(lower, "rke2"),
		strings.Contains(lower, "rancher"),
		strings.Contains(lower, "helm"),
		strings.Contains(lower, "chart"):
		setLayerSentryInstallProgress(g, "Configuring Kubernetes and platform services", 66)
	case strings.Contains(lower, "longhorn"),
		strings.Contains(lower, "storage"),
		strings.Contains(lower, "network"),
		strings.Contains(lower, "kube-vip"),
		strings.Contains(lower, "multus"),
		strings.Contains(lower, "cni"):
		setLayerSentryInstallProgress(g, "Configuring networking and storage", 78)
	}
}

func captureLayerSentryInstallOutput(g *gocui.Gui, cmdName, panel, logPrefix string, reader io.Reader, lock *sync.Mutex) {
	scanner := bufio.NewScanner(reader)
	scanner.Split(ScanLines)

	for scanner.Scan() {
		line := scanner.Text()
		// Preserve every native line in the normal installation logs for
		// troubleshooting, including package-manager output.
		logrus.Infof("%s: %s", logPrefix, line)
		if cmdName == layersentryNativeInstaller {
			updateLayerSentryInstallProgressFromOutput(g, line)
			continue
		}

		// Preserve upstream visible output behavior for other commands.
		lock.Lock()
		printToPanel(g, line, panel)
		lock.Unlock()
	}
	if err := scanner.Err(); err != nil {
		logrus.Warnf("%s output scanner failed: %v", logPrefix, err)
	}
}

'''
    text = insert_before_once(
        text,
        helper_anchor,
        helper_block,
        helper_marker,
        "LayerSentry progress helper insertion",
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
    new_install = '''\tsetLayerSentryInstallProgress(g, "Installing base operating system", 32)\n\tif err := execute(ctx, g, env, layersentryNativeInstaller); err != nil {\n'''
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

    required_util = (
        "func captureLayerSentryInstallOutput(",
        "cmdName == layersentryNativeInstaller",
        'setLayerSentryInstallProgress(g, "Validating installation media", 5)',
        'setLayerSentryInstallProgress(g, "Preparing system disks", 18)',
        'setLayerSentryInstallProgress(g, "Installing base operating system", 32)',
        'setLayerSentryInstallProgress(g, "Installing LayerSentry packages", 48)',
        'setLayerSentryInstallProgress(g, "Configuring Kubernetes and platform services", 66)',
        'setLayerSentryInstallProgress(g, "Configuring networking and storage", 78)',
        'setLayerSentryInstallProgress(g, "Applying LayerSentry branding and defaults", 88)',
        'setLayerSentryInstallProgress(g, "Finalizing installation", 96)',
        'setLayerSentryInstallProgress(g, "LayerSentry installation completed", 100)',
        'logrus.Infof("%s: %s", logPrefix, line)',
    )
    for marker in required_util:
        if marker not in util:
            raise SystemExit(f"LayerSentry installer UX transform missing marker: {marker}")

    if 'installV.SetContent(renderLayerSentryInstallProgress("Validating installation media", 0))' not in panels:
        raise SystemExit("LayerSentry installer UX transform did not seed the install panel")
    if "installV.Autoscroll = false" not in panels:
        raise SystemExit("LayerSentry installer UX transform did not disable raw-output scrolling")

    execute_start = util.index(
        "func execute(ctx context.Context, g *gocui.Gui, env []string, cmdName string) error {\n"
    )
    execute_end = util.index("func dropCR(data []byte) []byte {\n", execute_start)
    execute_region = util[execute_start:execute_end]
    if 'printToPanelAndLog(g, installPanel, "[stderr]", stderr, &writeLock)' in execute_region:
        raise SystemExit("raw native stderr is still copied directly to the main installation panel")
    if 'printToPanelAndLog(g, installPanel, "[stdout]", stdout, &writeLock)' in execute_region:
        raise SystemExit("raw native stdout is still copied directly to the main installation panel")


if __name__ == "__main__":
    patch_util()
    patch_panels()
    validate_result()
    print("LAYERSENTRY INSTALLER MILESTONE UX TRANSFORM: PASS")
