[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$IsoPath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SwitchName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$VmRoot,

    [string[]]$VmNames = @("sen1", "sen2", "sen3"),

    [string[]]$NodeAddresses = @("10.10.10.11", "10.10.10.12", "10.10.10.13"),

    [ValidateRange(1, 64)]
    [int]$ProcessorCount = 10,

    [ValidateRange(8, 1024)]
    [int]$StartupMemoryGiB = 32,

    [ValidateRange(40, 4096)]
    [int]$OsDiskGiB = 100,

    [ValidateRange(40, 16384)]
    [int]$DataDiskGiB = 300,

    [ValidateRange(0, 4094)]
    [int]$VlanId = 0,

    [string]$Gateway = "",

    [string[]]$DnsServers = @(),

    [string]$ClusterVip = "",

    [ValidateNotNullOrEmpty()]
    [string]$ApprovedNtpServer = "time.google.com",

    [string]$EvidenceDirectory = "",

    [switch]$AllowNonExternalSwitch,

    [switch]$Recreate,

    [switch]$StartVMs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Candidate = [ordered]@{
    product              = "LayerSentry"
    productVersion       = "1.0"
    harvesterVersion     = "v1.8.2"
    installerCommit      = "a104eab8cc5eca42b7ef002fc96561a21be3f163"
    buildWorkflowRunId   = "33479776571"
    buildJobId           = "99766588639"
    artifactId           = "9790788698"
    isoFilename          = "layersentry-v1.0-harvester-v1.8.2-amd64.iso"
    isoBytes             = [int64]8180137984
    isoSha512            = "7f1cd57c363f3b6b592fcbfb90d810c8f12f881e14e097fe17b2833250ee9e57a9831e4398147bd612bc7e3a36a4c45751019473e60eeaa263e5660c996feb81"
    startingClassification = "BUILD_GOOD"
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script from an elevated Windows PowerShell session."
    }
}

function Assert-HyperVAvailable {
    $requiredCommands = @(
        "Get-VM",
        "New-VM",
        "Remove-VM",
        "Start-VM",
        "Stop-VM",
        "Get-VMSwitch",
        "New-VHD",
        "Get-VHD",
        "Set-VM",
        "Set-VMProcessor",
        "Get-VMProcessor",
        "Set-VMFirmware",
        "Get-VMFirmware",
        "Add-VMDvdDrive",
        "Get-VMDvdDrive",
        "Add-VMHardDiskDrive",
        "Get-VMHardDiskDrive",
        "Set-VMNetworkAdapter",
        "Get-VMNetworkAdapter",
        "Set-VMNetworkAdapterVlan"
    )

    foreach ($command in $requiredCommands) {
        if (-not (Get-Command -Name $command -ErrorAction SilentlyContinue)) {
            throw "Required Hyper-V command '$command' is not available. Install/enable Hyper-V management tools first."
        }
    }
}

function Get-NormalizedFullPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return [System.IO.Path]::GetFullPath($Path).TrimEnd("\")
}

function Test-PathIsUnderRoot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CandidatePath,

        [Parameter(Mandatory = $true)]
        [string]$RootPath
    )

    $candidateFull = (Get-NormalizedFullPath -Path $CandidatePath) + "\"
    $rootFull = (Get-NormalizedFullPath -Path $RootPath) + "\"
    return $candidateFull.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)
}

function Remove-OwnedQualificationVm {
    param(
        [Parameter(Mandatory = $true)]
        [Microsoft.HyperV.PowerShell.VirtualMachine]$Vm,

        [Parameter(Mandatory = $true)]
        [string]$OwnedRoot
    )

    if (-not (Test-PathIsUnderRoot -CandidatePath $Vm.Path -RootPath $OwnedRoot)) {
        throw "Refusing to recreate VM '$($Vm.Name)' because its configuration path '$($Vm.Path)' is outside qualification root '$OwnedRoot'."
    }

    if ($Vm.State -ne "Off") {
        Stop-VM -VM $Vm -TurnOff -Force
    }

    Remove-VM -VM $Vm -Force
}

Assert-Administrator
Assert-HyperVAvailable

if ($VmNames.Count -lt 1) {
    throw "At least one VM name is required."
}

if (($VmNames | Select-Object -Unique).Count -ne $VmNames.Count) {
    throw "VM names must be unique."
}

if ($NodeAddresses.Count -ne $VmNames.Count) {
    throw "NodeAddresses count ($($NodeAddresses.Count)) must match VmNames count ($($VmNames.Count))."
}

$resolvedIso = (Resolve-Path -LiteralPath $IsoPath).ProviderPath
$isoItem = Get-Item -LiteralPath $resolvedIso
if ($isoItem.PSIsContainer) {
    throw "IsoPath must point to the ISO file, not a directory."
}

if ($isoItem.Name -ne $Candidate.isoFilename) {
    throw "Unexpected ISO filename '$($isoItem.Name)'. Required filename: '$($Candidate.isoFilename)'."
}

if ([int64]$isoItem.Length -ne $Candidate.isoBytes) {
    throw "ISO byte-size mismatch. Expected $($Candidate.isoBytes), found $($isoItem.Length)."
}

$actualSha512 = (Get-FileHash -LiteralPath $resolvedIso -Algorithm SHA512).Hash.ToLowerInvariant()
if ($actualSha512 -ne $Candidate.isoSha512) {
    throw "ISO SHA-512 mismatch. Refusing to create qualification VMs."
}

$vmRootFull = Get-NormalizedFullPath -Path $VmRoot
New-Item -ItemType Directory -Path $vmRootFull -Force | Out-Null

if ([string]::IsNullOrWhiteSpace($EvidenceDirectory)) {
    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
    $EvidenceDirectory = Join-Path $vmRootFull "evidence\$timestamp"
}
$evidenceFull = Get-NormalizedFullPath -Path $EvidenceDirectory
New-Item -ItemType Directory -Path $evidenceFull -Force | Out-Null

$transcriptPath = Join-Path $evidenceFull "prepare-hyperv-qualification.transcript.txt"
$transcriptStarted = $false
try {
    Start-Transcript -LiteralPath $transcriptPath -Force | Out-Null
    $transcriptStarted = $true
}
catch {
    Write-Warning "PowerShell transcript could not be started: $($_.Exception.Message)"
}

try {
    $vmSwitch = Get-VMSwitch -Name $SwitchName -ErrorAction Stop
    if ((-not $AllowNonExternalSwitch) -and ($vmSwitch.SwitchType.ToString() -ne "External")) {
        throw "VMSwitch '$SwitchName' is '$($vmSwitch.SwitchType)'. Production qualification requires an External switch unless -AllowNonExternalSwitch is explicitly supplied."
    }

    $memoryBytes = [uint64]$StartupMemoryGiB * 1GB
    $osDiskBytes = [uint64]$OsDiskGiB * 1GB
    $dataDiskBytes = [uint64]$DataDiskGiB * 1GB

    $preparedNames = New-Object System.Collections.Generic.List[string]

    for ($index = 0; $index -lt $VmNames.Count; $index++) {
        $vmName = $VmNames[$index]
        $vmPath = Join-Path $vmRootFull $vmName
        $diskPath = Join-Path $vmPath "Disks"
        $osDiskPath = Join-Path $diskPath "$vmName-os.vhdx"
        $dataDiskPath = Join-Path $diskPath "$vmName-data.vhdx"

        $existingVm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
        if ($null -ne $existingVm) {
            if (-not $Recreate) {
                throw "VM '$vmName' already exists. Use -Recreate only when it is owned by this qualification root."
            }

            Remove-OwnedQualificationVm -Vm $existingVm -OwnedRoot $vmRootFull
        }

        if (Test-Path -LiteralPath $vmPath) {
            if (-not $Recreate) {
                throw "VM directory '$vmPath' already exists. Use -Recreate only after confirming it belongs to this qualification."
            }

            Remove-Item -LiteralPath $vmPath -Recurse -Force
        }

        New-Item -ItemType Directory -Path $diskPath -Force | Out-Null
        New-VHD -Path $osDiskPath -Dynamic -SizeBytes $osDiskBytes | Out-Null
        New-VHD -Path $dataDiskPath -Dynamic -SizeBytes $dataDiskBytes | Out-Null

        New-VM `
            -Name $vmName `
            -Generation 2 `
            -Path $vmPath `
            -MemoryStartupBytes $memoryBytes `
            -VHDPath $osDiskPath `
            -SwitchName $SwitchName | Out-Null

        Set-VM `
            -Name $vmName `
            -DynamicMemoryEnabled $false `
            -AutomaticStartAction Nothing `
            -AutomaticStopAction ShutDown `
            -CheckpointType ProductionOnly

        $setVmCommand = Get-Command -Name Set-VM
        if ($setVmCommand.Parameters.ContainsKey("AutomaticCheckpointsEnabled")) {
            Set-VM -Name $vmName -AutomaticCheckpointsEnabled $false
        }

        Set-VMProcessor `
            -VMName $vmName `
            -Count $ProcessorCount `
            -ExposeVirtualizationExtensions $true

        Set-VMNetworkAdapter `
            -VMName $vmName `
            -MacAddressSpoofing On `
            -DhcpGuard Off `
            -RouterGuard Off

        if ($VlanId -gt 0) {
            Set-VMNetworkAdapterVlan -VMName $vmName -Access -VlanId $VlanId
        }

        Add-VMHardDiskDrive -VMName $vmName -Path $dataDiskPath
        Add-VMDvdDrive -VMName $vmName -Path $resolvedIso

        $dvdDrive = Get-VMDvdDrive -VMName $vmName | Where-Object { $_.Path -eq $resolvedIso } | Select-Object -First 1
        if ($null -eq $dvdDrive) {
            throw "Unable to locate the attached LayerSentry ISO DVD drive for VM '$vmName'."
        }

        Set-VMFirmware `
            -VMName $vmName `
            -EnableSecureBoot Off `
            -FirstBootDevice $dvdDrive

        $preparedNames.Add($vmName)
    }

    if ($StartVMs) {
        foreach ($vmName in $preparedNames) {
            Start-VM -Name $vmName | Out-Null
        }
    }

    $vmEvidence = foreach ($vmName in $preparedNames) {
        $vm = Get-VM -Name $vmName
        $processor = Get-VMProcessor -VMName $vmName
        $network = Get-VMNetworkAdapter -VMName $vmName | Select-Object -First 1
        $hardDisks = Get-VMHardDiskDrive -VMName $vmName
        $dvd = Get-VMDvdDrive -VMName $vmName | Select-Object -First 1
        $nodeIndex = [Array]::IndexOf($VmNames, $vmName)

        [ordered]@{
            name                            = $vm.Name
            intendedAddress                 = $NodeAddresses[$nodeIndex]
            state                           = $vm.State.ToString()
            generation                      = $vm.Generation
            configurationPath               = $vm.Path
            processorCount                  = $processor.Count
            exposeVirtualizationExtensions  = [bool]$processor.ExposeVirtualizationExtensions
            startupMemoryBytes              = [int64]$vm.MemoryStartup
            dynamicMemoryEnabled            = [bool]$vm.DynamicMemoryEnabled
            secureBoot                     = (Get-VMFirmware -VMName $vmName).SecureBoot.ToString()
            switchName                      = $network.SwitchName
            macAddress                      = $network.MacAddress
            macAddressSpoofing              = $network.MacAddressSpoofing.ToString()
            vlanId                          = $VlanId
            hardDisks                       = @($hardDisks | ForEach-Object {
                [ordered]@{
                    controllerType     = $_.ControllerType.ToString()
                    controllerNumber   = $_.ControllerNumber
                    controllerLocation = $_.ControllerLocation
                    path               = $_.Path
                    bytes              = [int64](Get-VHD -Path $_.Path).Size
                }
            })
            installationMedia               = $dvd.Path
        }
    }

    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $manifest = [ordered]@{
        apiVersion = "qualification.layersentry.io/v1"
        kind = "HyperVInstallationPreparationEvidence"
        metadata = [ordered]@{
            generatedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
            qualificationState = "HYPERV_VM_PREPARED_INSTALL_REVIEW_REQUIRED"
            buildGood = $true
            bootSmokeGood = $false
            installGood = $false
            airgapGood = $false
            releaseGood = $false
        }
        candidate = $Candidate
        host = [ordered]@{
            computerName = $env:COMPUTERNAME
            osCaption = $osInfo.Caption
            osVersion = $osInfo.Version
            osBuildNumber = $osInfo.BuildNumber
            powershellVersion = $PSVersionTable.PSVersion.ToString()
        }
        network = [ordered]@{
            switchName = $vmSwitch.Name
            switchType = $vmSwitch.SwitchType.ToString()
            vlanId = $VlanId
            gateway = $Gateway
            dnsServers = @($DnsServers)
            clusterVip = $ClusterVip
        }
        installerInputs = [ordered]@{
            nodeAddresses = @($NodeAddresses)
            approvedNtpServer = $ApprovedNtpServer
            note = "The Hyper-V harness records these values but does not inject installer answers. Enter and verify them in the editable LayerSentry installer."
        }
        requestedVmProfile = [ordered]@{
            processorCount = $ProcessorCount
            startupMemoryGiB = $StartupMemoryGiB
            osDiskGiB = $OsDiskGiB
            dataDiskGiB = $DataDiskGiB
            generation = 2
            secureBoot = "Off"
            nestedVirtualization = $true
            macAddressSpoofing = "On"
        }
        virtualMachines = @($vmEvidence)
        gateBoundary = [ordered]@{
            statement = "VM preparation is not installation qualification."
            requiredNextEvidence = @(
                "installer UI screenshots for every node",
                "successful installation completion",
                "ISO detached from every VM",
                "reboot from installed OS disk",
                "node and cluster readiness",
                "workload or VM smoke evidence"
            )
        }
    }

    $manifestPath = Join-Path $evidenceFull "hyperv-install-preparation.json"
    $manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    $manifestSha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    "$manifestSha256  hyperv-install-preparation.json" |
        Set-Content -LiteralPath (Join-Path $evidenceFull "hyperv-install-preparation.json.sha256") -Encoding ASCII

    $operatorSteps = @"
LayerSentry Hyper-V installation qualification

Candidate ISO:
  $($Candidate.isoFilename)
  SHA-512: $($Candidate.isoSha512)
  Bytes: $($Candidate.isoBytes)
  Build run: $($Candidate.buildWorkflowRunId)
  Artifact ID: $($Candidate.artifactId)

Prepared VMs:
  $($preparedNames -join ", ")

Installer values to enter and verify:
  Node addresses: $($NodeAddresses -join ", ")
  Gateway: $Gateway
  DNS servers: $($DnsServers -join ", ")
  Cluster VIP: $ClusterVip
  NTP server: $ApprovedNtpServer

Required gate sequence:
  1. Capture the LayerSentry installer UI and entered values.
  2. Complete installation on the required node set.
  3. Shut down each VM.
  4. Detach the ISO from every virtual DVD drive.
  5. Set the installed OS disk as first boot device.
  6. Reboot and capture the installed-system console.
  7. Verify node/cluster readiness and run workload/VM smoke tests.
  8. Preserve evidence against the exact ISO identity above.

This preparation does not grant BOOT_SMOKE_GOOD, INSTALL_GOOD, AIRGAP_GOOD, or RELEASE_GOOD.
"@
    $operatorSteps | Set-Content -LiteralPath (Join-Path $evidenceFull "OPERATOR-NEXT-STEPS.txt") -Encoding UTF8

    Write-Host ""
    Write-Host "LayerSentry Hyper-V qualification VMs prepared successfully."
    Write-Host "Evidence directory: $evidenceFull"
    Write-Host "Classification remains BUILD_GOOD; installation review is still required."
}
finally {
    if ($transcriptStarted) {
        Stop-Transcript | Out-Null
    }
}
