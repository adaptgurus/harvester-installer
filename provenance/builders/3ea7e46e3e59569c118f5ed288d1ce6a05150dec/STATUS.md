# LayerSentry v1.0 immutable builder/toolchain candidate

- Source commit: `3ea7e46e3e59569c118f5ed288d1ce6a05150dec`
- Builder image: `ghcr.io/adaptgurus/layersentry-full-offline-builder@sha256:329e933d3fff98cd4d0c94ab803b7fb24b28a3cd1352661241170c57169e476b`
- Builder source alias: `ghcr.io/adaptgurus/layersentry-full-offline-builder:source-3ea7e46e3e59569c118f5ed288d1ce6a05150dec`
- Platform: `linux/amd64`
- Rootfs layers: 10
- Inventoried tool binaries: 25
- Reviewed toolchain lock records: 29
- Production lock complete: **false**
- Release approval: **false**

The production build path consumes the builder by OCI digest, starts an internal
Docker daemon from that image, and does not mount the host Docker socket.
