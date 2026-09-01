# Reproducibility boundary

The LayerSentry controller binary is compiled twice with a blank Go build ID,
`-trimpath`, disabled VCS injection, static Linux/AMD64 linking, and link-time
version/source values. Its file mode and modification time are normalized to
the exact source commit epoch before the scratch OCI layer is constructed.

The Docker build context, BuildKit image configuration, image history, and
scratch root-filesystem layer are normalized to the same source-commit epoch.
The controller lock is accepted only when two independent candidate builds and
the separate no-network rebuild produce the same binary SHA-256, image
configuration digest, and root-filesystem diff ID.

This is repository and container-build qualification. Hyper-V installation,
three-node cluster formation, storage, networking, HA, upgrade, and air-gap
runtime qualification are separate lab gates and must not be inferred from a
successful container-image lock.
