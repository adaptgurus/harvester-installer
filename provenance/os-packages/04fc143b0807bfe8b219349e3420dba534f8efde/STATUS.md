# LayerSentry v1.0 Harvester OS/package input evidence

- Source commit: `04fc143b0807bfe8b219349e3420dba534f8efde`
- Product: LayerSentry v1.0
- Embedded platform: Harvester v1.8.2
- Base OS alias observed: `docker.io/rancher/harvester-os:v1.8-20260806`
- Base OS consumed by digest: `docker.io/rancher/harvester-os@sha256:d437600ddc5e809cd22d9a6ddfc3c10328ac88440cef2930aa73aaf36b4178b4`
- Platform: `linux/amd64`
- Rootfs layers: 19
- Installed RPM packages: 507
- Firmware records: 5196
- Reviewed package/input lock records: 11
- Production lock complete: **false**
- Release approval: **false**

The exact OCI digest covers the base root filesystem. Deterministic package,
kernel, initrd, firmware, repository, OS-tool and LayerSentry-overlay manifests
provide independently reviewable evidence of the inputs consumed by the ISO path.
