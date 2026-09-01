# Reproducibility and immutable-image boundary

The LayerSentry controller binary is compiled twice with a blank Go build ID,
`-trimpath`, disabled VCS injection, static Linux/AMD64 linking, and link-time
version/source values. File mode and modification time are normalized to the
exact source-commit epoch. The two binaries must be byte-for-byte identical.

Docker's local image exporter adds daemon-controlled image metadata, so a local
image ID is not treated as a reproducibility oracle. One source-bound scratch
image is validated, self-tested, pushed, and recorded by its immutable registry
manifest digest. Its configuration digest, root-filesystem diff ID, platform,
non-root user, entrypoint, command, labels, and SPDX SBOM are retained as
reviewed evidence.

A separate build from a Git archive of the locked source commit must reproduce
the exact controller binary SHA-256. The build then pulls the reviewed OCI
manifest by digest, verifies the locked RepoDigest, configuration digest,
root-filesystem diff ID and runtime configuration, reruns the self-test, and
only then tags that exact immutable object for the offline image archive.

This is repository and container-build qualification. Hyper-V installation,
three-node cluster formation, storage, networking, HA, upgrade, and air-gap
runtime qualification are separate lab gates and must not be inferred from a
successful controller-image lock.
