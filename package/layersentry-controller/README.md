# LayerSentry bootstrap controller image

This package builds the source-bound `ghcr.io/adaptgurus/layersentry-controller`
image for LayerSentry v1.0 with embedded Harvester v1.8.2.

## Current responsibility

The v1.0 image is deliberately limited to pre-Rancher bootstrap validation. It
provides health, readiness, immutable build identity, capability discovery and
strict validation of platform connectivity, timezone, NTP, DNS, proxy and
registry-mirror settings.

It does **not**:

- execute shell commands;
- mutate Harvester, Rancher, Kubernetes, storage or network resources;
- install optional services;
- create credentials;
- imply runtime or production qualification merely because it is present in the
  offline ISO.

The image reports the lifecycle state `BUNDLED_NOT_INSTALLED`. Installation and
runtime qualification require separate release evidence and an approved
bootstrap workflow.

## Security posture

- `FROM scratch` runtime image;
- statically linked Go binary;
- non-root UID/GID `65532:65532`;
- no package manager, shell or outbound client in the runtime image;
- one-megabyte request limit and strict JSON decoding;
- localhost listen address by default in the binary;
- source commit, version and build epoch embedded at link time;
- OCI image locked and consumed by SHA-256 digest.

The image-level default listens on `0.0.0.0:9443` so an explicitly deployed
Kubernetes workload can expose it. The binary itself defaults to
`127.0.0.1:9443` when run without image arguments.
