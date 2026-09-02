package console

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/jroimartin/gocui"
	"github.com/sirupsen/logrus"
)

const layerSentryProgressBarWidth = 32

var layerSentryInstallProgress = struct {
	sync.Mutex
	percent int
}{percent: -1}

func resetLayerSentryInstallProgress() {
	layerSentryInstallProgress.Lock()
	layerSentryInstallProgress.percent = -1
	layerSentryInstallProgress.Unlock()
}

func renderLayerSentryInstallProgress(stage string, percent int) string {
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}

	filled := percent * layerSentryProgressBarWidth / 100
	bar := strings.Repeat("#", filled) + strings.Repeat("-", layerSentryProgressBarWidth-filled)

	return fmt.Sprintf(`
                 LAYERSENTRY
                    v1.0

             Installing LayerSentry

Stage: %s

[%s] %d%%

Please wait. Do not power off the system.
`, stage, bar, percent)
}

func setLayerSentryInstallProgress(g *gocui.Gui, stage string, percent int) {
	if g == nil {
		return
	}
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}

	layerSentryInstallProgress.Lock()
	if percent < layerSentryInstallProgress.percent {
		layerSentryInstallProgress.Unlock()
		return
	}
	layerSentryInstallProgress.percent = percent
	layerSentryInstallProgress.Unlock()

	g.Update(func(gui *gocui.Gui) error {
		view, err := gui.View(installPanel)
		if err != nil {
			return nil
		}
		view.Clear()
		_ = view.SetCursor(0, 0)
		_ = view.SetOrigin(0, 0)
		view.Autoscroll = false
		view.Wrap = true
		_, err = fmt.Fprint(view, renderLayerSentryInstallProgress(stage, percent))
		return err
	})
}

func validateLayerSentryInstallMedia() error {
	info, err := os.Stat("/usr/sbin/harv-install")
	if err != nil {
		return fmt.Errorf("installer executable is unavailable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("installer executable is not an executable regular file")
	}
	return nil
}

func captureLayerSentryInstallOutput(g *gocui.Gui, commandName, logPrefix string, reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	scanner.Split(ScanLines)

	for scanner.Scan() {
		line := scanner.Text()
		// Preserve the complete native installer stream in the normal installation log.
		// The customer-facing install panel intentionally receives only milestone state.
		logrus.Infof("%s: %s", logPrefix, line)
		if commandName == "/usr/sbin/harv-install" {
			observeLayerSentryInstallMilestone(g, line)
		}
	}
	if err := scanner.Err(); err != nil {
		logrus.Errorf("%s: failed reading installer output: %v", logPrefix, err)
	}
}

func observeLayerSentryInstallMilestone(g *gocui.Gui, line string) {
	value := strings.ToLower(strings.TrimSpace(line))
	if value == "" {
		return
	}

	switch {
	case containsAnyLayerSentryMilestone(value,
		"zypper", "rpm", "package install", "installing package", "install packages", "installing packages"):
		setLayerSentryInstallProgress(g, "Installing LayerSentry packages", 55)
	case containsAnyLayerSentryMilestone(value,
		"rke2", "kubernetes", "containerd", "rancherd"):
		setLayerSentryInstallProgress(g, "Configuring Kubernetes and platform services", 70)
	case containsAnyLayerSentryMilestone(value,
		"longhorn", "network config", "networking", "storage config", "configuring storage"):
		setLayerSentryInstallProgress(g, "Configuring networking and storage", 82)
	case containsAnyLayerSentryMilestone(value,
		"layersentry branding", "private-label", "private label", "branding defaults"):
		setLayerSentryInstallProgress(g, "Applying LayerSentry branding and defaults", 90)
	}
}

func containsAnyLayerSentryMilestone(value string, markers ...string) bool {
	for _, marker := range markers {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}
