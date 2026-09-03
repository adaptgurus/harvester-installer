# LayerSentry Hyper-V installation qualification

This harness prepares clean Hyper-V virtual machines for installation testing of the exact retained **BUILD-GOOD candidate** LayerSentry ISO. It does not rebuild, download, rename, or replace the candidate. This Hyper-V environment is a POC/reference qualification environment and does not by itself constitute physical-production certification.

## Locked candidate

- ISO: `layersentry-v1.0-harvester-v1.8.2-amd64.iso`
- Build source: `7355b893cae5cef00516f569bd406c5eae985259`
- Build workflow: `LayerSentry v1.0 generated offline image-set lock`
- Build workflow run: `33716608731`
- Build job ID: `100527008929`
- ISO artifact ID: `9879403683`
- ISO artifact name: `layersentry-v1.0-harvester-v1.8.2-amd64-offline-7355b893cae5cef00516f569bd406c5eae985259`
- ISO bytes: `9369419776`
- ISO SHA-256: `6d337528fe17714a902b1ca3ab9ed5867fb1c976330bc115a37d5688ac871da4`
- ISO SHA-512: `e19d266511f440e125dc7cf2da7a6d716b3d60121d7f96fc5aa0f65d53868d281dcc5ac98afd70f994c68750df2f0ac70cbfe512a38053a657765c7f40fd215a`
- Completed dependency-lock commit: `0a0360023331fc5480cfee7c0cd9005cfa1ddc05`
- Completed evidence audit run: `33722491906`
- Completed evidence audit artifact ID: `9880717996`

The script exits before VM creation if the filename, byte count, SHA-256, or SHA-512 differs. The candidate identity is intentionally immutable for this qualification cycle.

## Default POC profile

Each VM is created as:

- Hyper-V Generation 2
- 10 vCPU
- 32 GiB fixed memory
- 100 GiB dynamic OS VHDX
- 300 GiB dynamic data VHDX
- Secure Boot disabled
- nested virtualization enabled
- MAC-address spoofing enabled
- production checkpoints only; automatic checkpoints disabled where supported

The default node names and intended installer addresses are:

- `sen1` — `10.10.10.11`
- `sen2` — `10.10.10.12`
- `sen3` — `10.10.10.13`

The script records network, DNS, VIP, and NTP inputs as evidence, but it deliberately does not inject installer answers. Enter and verify them in the LayerSentry installer. The NTP field remains editable; `time.google.com` is only the connected-install starting value. Use an approved internal NTP source for the true-air-gap test.

## Run

Run from an elevated Windows PowerShell session on the Hyper-V host:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force

.\scripts\prepare-production-hyperv-install-qualification.ps1 `
  -IsoPath "D:\ISO\layersentry-v1.0-harvester-v1.8.2-amd64.iso" `
  -SwitchName "LayerSentryExternal" `
  -VmRoot "D:\LayerSentry-Qualification\VMs" `
  -Gateway "10.10.10.1" `
  -DnsServers "10.10.10.2" `
  -ClusterVip "10.10.10.10" `
  -ApprovedNtpServer "10.10.10.2" `
  -StartVMs
```

By default, the selected virtual switch must be External. A non-external switch requires the explicit `-AllowNonExternalSwitch` override and must be documented in the evidence.

Existing VMs are never modified. `-Recreate` removes an existing VM only when its configuration path is under the supplied qualification root; the script refuses to remove a same-named VM located elsewhere.

## Evidence produced

A timestamped evidence directory contains:

- `prepare-hyperv-qualification.transcript.txt`
- `hyperv-install-preparation.json`
- `hyperv-install-preparation.json.sha256`
- `OPERATOR-NEXT-STEPS.txt`

The manifest binds the VM configuration to the exact ISO identity and explicitly leaves these gates false:

- `bootSmokeGood`
- `installGood`
- `airgapGood`
- `releaseGood`

## Installation gate

After installer completion:

1. Capture installer screens and the entered network/NTP values.
2. Shut down all test VMs.
3. Detach the ISO from every VM.
4. Place the installed OS disk first in firmware boot order.
5. Reboot from disk and capture the installed-system console.
6. Verify node readiness and three-node cluster formation.
7. Verify LayerSentry branding and installer milestone UX on the installed candidate.
8. Verify the production-default observability add-ons and only the intended opt-in add-ons.
9. Run VM/workload and storage smoke tests.
10. Repeat the required validation with public Internet blocked and an approved internal NTP/DNS path.
11. Preserve all evidence against the exact checksum-locked candidate.

VM preparation alone must never be reported as `INSTALL_GOOD`, `AIRGAP_GOOD`, or production approval.
