# Reproducibility boundary

The LayerSentry controller candidate binary is compiled twice with a blank Go
build ID, `-trimpath`, disabled VCS injection, static Linux/AMD64 linking, and
link-time version/source values. File mode and modification time are normalized
to the exact source-commit epoch before the scratch OCI image is built. Two
independent candidate image builds must produce the same binary SHA-256, image
configuration digest, root-filesystem diff ID, runtime configuration, and
self-test output before the image can be reviewed.

A separate build from a Git archive of the locked source commit proves the same
controller binary SHA-256. The local Docker image from that second source tree is
not bundled because Docker's local exporter may encode non-runtime tar metadata
differently. Instead, the build pulls the exact reviewed OCI manifest by digest,
verifies its RepoDigest, configuration digest, root-filesystem diff ID, platform,
non-root user, entrypoint, command, labels, and self-test result, and only then
tags that immutable object for inclusion in the offline image archive.

This is repository and container-build qualification. Hyper-V installation,
three-node cluster formation, storage, networking, HA, upgrade, and air-gap
runtime qualification are separate lab gates and must not be inferred from a
successful controller-image lock.
