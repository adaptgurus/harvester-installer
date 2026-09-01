# LayerSentry Hyper-V installation qualification

This harness prepares clean Hyper-V virtual machines for installation testing of the exact retained `BUILD_GOOD` LayerSentry ISO. It does not rebuild, download, rename, or replace the candidate.

## Locked candidate

- ISO: `layersentry-v1.0-harvester-v1.8.2-amd64.iso`
- Build source: `a104eab8cc5eca42b7ef002fc96561a21be3f163`
- Build workflow run: `33479776571`
- Artifact ID: `9790788698`
- Bytes: `8180137984`
- SHA-512: `7f1cd57c363f3b6b592fcbfb90d810c8f12f881e14e097fe17b2833250ee9e57a9831e4398147bd612bc7e3a36a4c45751019473e60eeaa263e5660c996feb81`

The script exits before VM creation if the filename, byte count, or SHA-512 differs.

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
7. Run VM/workload smoke tests.
8. Preserve all evidence against the exact checksum-locked candidate.

VM preparation alone must never be reported as `INSTALL_GOOD`.
