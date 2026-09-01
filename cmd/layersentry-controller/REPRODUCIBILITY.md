# Reproducibility boundary

The LayerSentry controller binary is compiled twice with a blank Go build ID,
`-trimpath`, disabled VCS injection, static Linux/AMD64 linking, and link-time
version/source values. Its file mode and modification time are normalized to
the exact source commit epoch before the scratch OCI layer is constructed.

The controller lock is accepted only when the candidate build and the separate
o-network rebuild produce the same binary SHA-256, image configuration digest,
and root filesystem diff ID.
