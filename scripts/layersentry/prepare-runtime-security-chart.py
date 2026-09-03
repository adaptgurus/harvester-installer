#!/usr/bin/env python3
"""Apply LayerSentry offline/OEM defaults to the pinned NeuVector core chart.

The transformation is intentionally narrow and fail-closed. It changes only
presentation and offline behavior; workload topology, RBAC, services, routes,
and security-engine functionality remain upstream NeuVector behavior.
"""
from __future__ import annotations

import argparse
from pathlib import Path

EXPECTED_VERSION = "2.10.3"
EXPECTED_APP_VERSION = "5.5.3"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("chart_dir", type=Path)
    args = parser.parse_args()

    chart_yaml = args.chart_dir / "Chart.yaml"
    values_yaml = args.chart_dir / "values.yaml"
    if not chart_yaml.is_file() or not values_yaml.is_file():
        raise SystemExit("NeuVector core chart is incomplete")

    chart = chart_yaml.read_text(encoding="utf-8")
    if f"version: {EXPECTED_VERSION}\n" not in chart:
        raise SystemExit("unexpected NeuVector chart version")
    if f"appVersion: {EXPECTED_APP_VERSION}\n" not in chart:
        raise SystemExit("unexpected NeuVector app version")
    chart = replace_once(
        chart,
        "description: Helm chart for NeuVector's core services\n",
        "description: LayerSentry Runtime Security powered by NeuVector core services\n",
        "chart description",
    )
    chart_yaml.write_text(chart, encoding="utf-8")

    values = values_yaml.read_text(encoding="utf-8")
    values = replace_once(
        values,
        "tag: 5.5.3\noem:\n",
        "tag: 5.5.3\noem: LayerSentry Runtime Security\n",
        "OEM product name",
    )
    values = replace_once(
        values,
        "  env:\n    ssl: true\n    envs: []\n",
        "  env:\n    ssl: true\n    envs:\n"
        "      - name: CUSTOM_PAGE_HEADER_CONTENT\n"
        "        value: \"TGF5ZXJTZW50cnkgUnVudGltZSBTZWN1cml0eQ==\"\n"
        "      - name: CUSTOM_PAGE_HEADER_COLOR\n"
        "        value: \"#0F172A\"\n"
        "      - name: CUSTOM_PAGE_FOOTER_COLOR\n"
        "        value: \"#111827\"\n",
        "manager visual branding",
    )
    values = replace_once(
        values,
        "  updater:\n    # If false, cve updater will not be installed\n    enabled: true\n",
        "  updater:\n    # Disabled by LayerSentry for deterministic full-offline operation.\n"
        "    # CVE database updates are supplied through reviewed offline update media.\n"
        "    enabled: false\n",
        "offline CVE updater policy",
    )
    values = replace_once(
        values,
        "      repository: neuvector/scanner\n      imagePullPolicy: Always\n      tag: \"6\"\n",
        "      repository: neuvector/scanner\n      imagePullPolicy: IfNotPresent\n      tag: \"6\"\n",
        "scanner offline pull policy",
    )

    required = (
        "prime:\n    enabled: false",
        "adapter:\n    enabled: false",
        "repository: neuvector/controller",
        "repository: neuvector/enforcer",
        "repository: neuvector/manager",
        "repository: neuvector/scanner",
    )
    for token in required:
        if token not in values:
            raise SystemExit(f"required NeuVector baseline token missing: {token!r}")
    if "repository: neuvector/updater\n" not in values or "enabled: false\n" not in values:
        raise SystemExit("offline updater transformation did not validate")

    values_yaml.write_text(values, encoding="utf-8")
    print("LAYERSENTRY RUNTIME SECURITY CHART TRANSFORM: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
