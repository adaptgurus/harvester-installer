[CmdletBinding()]
param(
    [string]$EvidenceDirectory = (Join-Path $env:RUNNER_TEMP "layersentry-hyperv-inventory"),
    [string[]]$ExpectedVmNames = @("sen1", "sen2", "sen3")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-CommandEvidence {
    param([Parameter(Mandatory = $true)][string]$Name)

    $command = Get-Command -Name $Name -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $command) {
        return [ordered]@{
            name = $Name
            available = $false
            source = $null
            version = $null
        }
    }

    $version = $null
    if ($null -ne $command.Version) {
        $version = $command.Version.ToString()
    }

    return [ordered]@{
        name = $Name
        available = $true
        source = $command.Source
        version = $version
    }
}

function Get-VmEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][bool]$Expected
    )

    $vm = Get-VM -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $vm) {
        return [ordered]@{
            name = $Name
            expected = $Expected
            exists = $false
            state = "ABSENT"
        }
    }

    $processor = Get-VMProcessor -VMName $Name
    $firmware = Get-VMFirmware -VMName $Name
    $networkAdapters = @(Get-VMNetworkAdapter -VMName $Name)
    $hardDisks = @(Get-VMHardDiskDrive -VMName $Name)
    $dvdDrives = @(Get-VMDvdDrive -VMName $Name)

    $networkEvidence = foreach ($adapter in $networkAdapters) {
        $vlan = Get-VMNetworkAdapterVlan -VMNetworkAdapter $adapter
        [ordered]@{
            name = $adapter.Name
            switchName = $adapter.SwitchName
            status = $adapter.Status.ToString()
            connected = [bool]$adapter.Connected
            macAddress = $adapter.MacAddress
            macAddressSpoofing = $adapter.MacAddressSpoofing.ToString()
            dhcpGuard = $adapter.DhcpGuard.ToString()
            routerGuard = $adapter.RouterGuard.ToString()
            vlanMode = $vlan.OperationMode.ToString()
            accessVlanId = $vlan.AccessVlanId
            ipAddresses = @($adapter.IPAddresses)
        }
    }

    $diskEvidence = foreach ($disk in $hardDisks) {
        $vhd = $null
        if (-not [string]::IsNullOrWhiteSpace($disk.Path) -and (Test-Path -LiteralPath $disk.Path)) {
            $vhd = Get-VHD -Path $disk.Path
        }
        [ordered]@{
            controllerType = $disk.ControllerType.ToString()
            controllerNumber = $disk.ControllerNumber
            controllerLocation = $disk.ControllerLocation
            path = $disk.Path
            pathExists = (-not [string]::IsNullOrWhiteSpace($disk.Path)) -and (Test-Path -LiteralPath $disk.Path)
            format = if ($null -ne $vhd) { $vhd.VhdFormat.ToString() } else { $null }
            type = if ($null -ne $vhd) { $vhd.VhdType.ToString() } else { $null }
            maximumBytes = if ($null -ne $vhd) { [int64]$vhd.Size } else { $null }
            fileBytes = if ($null -ne $vhd) { [int64]$vhd.FileSize } else { $null }
        }
    }

    return [ordered]@{
        name = $vm.Name
        expected = $Expected
        exists = $true
        state = $vm.State.ToString()
        status = $vm.Status
        generation = $vm.Generation
        version = $vm.Version.ToString()
        configurationPath = $vm.Path
        uptimeSeconds = [int64]$vm.Uptime.TotalSeconds
        processorCount = $processor.Count
        exposeVirtualizationExtensions = [bool]$processor.ExposeVirtualizationExtensions
        cpuUsagePercent = $vm.CPUUsage
        startupMemoryBytes = [int64]$vm.MemoryStartup
        assignedMemoryBytes = [int64]$vm.MemoryAssigned
        dynamicMemoryEnabled = [bool]$vm.DynamicMemoryEnabled
        automaticStartAction = $vm.AutomaticStartAction.ToString()
        automaticStopAction = $vm.AutomaticStopAction.ToString()
        checkpointType = $vm.CheckpointType.ToString()
        secureBoot = $firmware.SecureBoot.ToString()
        networkAdapters = @($networkEvidence)
        hardDisks = @($diskEvidence)
        dvdDrives = @($dvdDrives | ForEach-Object {
            [ordered]@{
                controllerNumber = $_.ControllerNumber
                controllerLocation = $_.ControllerLocation
                path = $_.Path
                mediaExists = (-not [string]::IsNullOrWhiteSpace($_.Path)) -and (Test-Path -LiteralPath $_.Path)
            }
        })
    }
}

New-Item -ItemType Directory -Path $EvidenceDirectory -Force | Out-Null
$EvidenceDirectory = (Resolve-Path -LiteralPath $EvidenceDirectory).ProviderPath
$inventoryPath = Join-Path $EvidenceDirectory "hyperv-lab-inventory.json"
$summaryPath = Join-Path $EvidenceDirectory "SUMMARY.md"
$errorPath = Join-Path $EvidenceDirectory "inventory-error.txt"

$administrator = Test-IsAdministrator
$requiredHyperVCommands = @(
    "Get-VMHost",
    "Get-VM",
    "Get-VMProcessor",
    "Get-VMFirmware",
    "Get-VMNetworkAdapter",
    "Get-VMNetworkAdapterVlan",
    "Get-VMHardDiskDrive",
    "Get-VMDvdDrive",
    "Get-VHD",
    "Get-VMSwitch"
)
$missingHyperVCommands = @($requiredHyperVCommands | Where-Object {
    -not (Get-Command -Name $_ -ErrorAction SilentlyContinue)
})

$inventory = $null
try {
    if (-not $administrator) {
        throw "The GitHub runner identity is not an elevated local administrator."
    }
    if ($missingHyperVCommands.Count -gt 0) {
        throw "Required Hyper-V commands are unavailable: $($missingHyperVCommands -join ', ')"
    }

    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem
    $vmHost = Get-VMHost
    $switches = @(Get-VMSwitch | Sort-Object Name)
    $allVms = @(Get-VM | Sort-Object Name)
    $expectedSet = @{}
    foreach ($name in $ExpectedVmNames) {
        $expectedSet[$name.ToLowerInvariant()] = $true
    }

    $vmEvidence = New-Object System.Collections.Generic.List[object]
    foreach ($name in $ExpectedVmNames) {
        $vmEvidence.Add((Get-VmEvidence -Name $name -Expected $true))
    }
    foreach ($vm in $allVms) {
        if (-not $expectedSet.ContainsKey($vm.Name.ToLowerInvariant())) {
            $vmEvidence.Add((Get-VmEvidence -Name $vm.Name -Expected $false))
        }
    }

    $expectedPresent = @($vmEvidence | Where-Object { $_.expected -and $_.exists }).Count
    $expectedRunning = @($vmEvidence | Where-Object { $_.expected -and $_.exists -and $_.state -eq "Running" }).Count
    $runnerServices = @(Get-Service -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -like "actions.runner*" -or $_.DisplayName -like "GitHub Actions Runner*"
    })

    $toolNames = @(
        "docker", "podman", "nerdctl", "kubectl", "helm", "git", "go",
        "pwsh", "powershell", "wsl", "Get-VM"
    )

    $inventory = [ordered]@{
        apiVersion = "qualification.layersentry.io/v1"
        kind = "HyperVLabInventory"
        metadata = [ordered]@{
            generatedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
            sourceRepository = $env:GITHUB_REPOSITORY
            sourceCommit = $env:GITHUB_SHA
            workflow = $env:GITHUB_WORKFLOW
            workflowRunId = $env:GITHUB_RUN_ID
            workflowRunAttempt = $env:GITHUB_RUN_ATTEMPT
            qualificationState = "INVENTORY_ONLY_NOT_INSTALL_QUALIFIED"
        }
        runner = [ordered]@{
            computerName = $env:COMPUTERNAME
            userName = [Security.Principal.WindowsIdentity]::GetCurrent().Name
            processUser = (& whoami.exe)
            administrator = $administrator
            runnerName = $env:RUNNER_NAME
            runnerOs = $env:RUNNER_OS
            runnerArch = $env:RUNNER_ARCH
            services = @($runnerServices | ForEach-Object {
                [ordered]@{
                    name = $_.Name
                    displayName = $_.DisplayName
                    status = $_.Status.ToString()
                    startType = $_.StartType.ToString()
                }
            })
        }
        host = [ordered]@{
            manufacturer = $computer.Manufacturer
            model = $computer.Model
            logicalProcessors = $computer.NumberOfLogicalProcessors
            totalPhysicalMemoryBytes = [int64]$computer.TotalPhysicalMemory
            osCaption = $os.Caption
            osVersion = $os.Version
            osBuildNumber = $os.BuildNumber
            powershellVersion = $PSVersionTable.PSVersion.ToString()
            hyperVHost = [ordered]@{
                logicalProcessorCount = $vmHost.LogicalProcessorCount
                memoryCapacityBytes = [int64]$vmHost.MemoryCapacity
                virtualMachinePath = $vmHost.VirtualMachinePath
                virtualHardDiskPath = $vmHost.VirtualHardDiskPath
                enableEnhancedSessionMode = [bool]$vmHost.EnableEnhancedSessionMode
            }
        }
        switches = @($switches | ForEach-Object {
            [ordered]@{
                name = $_.Name
                type = $_.SwitchType.ToString()
                id = $_.Id.ToString()
                netAdapterInterfaceDescription = $_.NetAdapterInterfaceDescription
                allowManagementOS = $_.AllowManagementOS
            }
        })
        virtualMachines = @($vmEvidence)
        tools = @($toolNames | ForEach-Object { Get-CommandEvidence -Name $_ })
        summary = [ordered]@{
            expectedVmNames = @($ExpectedVmNames)
            expectedVmCount = $ExpectedVmNames.Count
            expectedPresent = $expectedPresent
            expectedRunning = $expectedRunning
            allVmCount = $allVms.Count
            hyperVManagementReady = $true
            dockerRequiredOnHyperVHostForVmInventory = $false
            dockerRequiredInsideHarvesterGuestNodes = $false
            harvesterRuntime = "containerd"
            newVmCreatedByThisWorkflow = $false
            destructiveChangesMade = $false
            installationQualified = $false
            airgapQualified = $false
            releaseQualified = $false
        }
    }

    $inventory | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $inventoryPath -Encoding UTF8
    $hash = (Get-FileHash -LiteralPath $inventoryPath -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  hyperv-lab-inventory.json" | Set-Content -LiteralPath "$inventoryPath.sha256" -Encoding ASCII

    @"
# LayerSentry Hyper-V lab inventory

- Generated: $($inventory.metadata.generatedAtUtc)
- Runner: $($inventory.runner.runnerName) as $($inventory.runner.userName)
- Elevated administrator: $administrator
- Hyper-V management ready: true
- Expected VMs present: $expectedPresent/$($ExpectedVmNames.Count)
- Expected VMs running: $expectedRunning/$($ExpectedVmNames.Count)
- Total VMs found: $($allVms.Count)
- Docker required inside Harvester VMs: **false**
- Harvester container runtime: **containerd**
- VMs created or modified by this workflow: **false**
- Installation qualification: **not performed**
"@ | Set-Content -LiteralPath $summaryPath -Encoding UTF8

    Write-Host "HYPER-V INVENTORY: PASS"
    Write-Host "Expected VMs present: $expectedPresent/$($ExpectedVmNames.Count)"
    Write-Host "Expected VMs running: $expectedRunning/$($ExpectedVmNames.Count)"
}
catch {
    $_ | Out-String | Set-Content -LiteralPath $errorPath -Encoding UTF8
    $failure = [ordered]@{
        apiVersion = "qualification.layersentry.io/v1"
        kind = "HyperVLabInventoryFailure"
        generatedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
        computerName = $env:COMPUTERNAME
        userName = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        administrator = $administrator
        missingHyperVCommands = @($missingHyperVCommands)
        error = $_.Exception.Message
        destructiveChangesMade = $false
    }
    $failure | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $inventoryPath -Encoding UTF8
    throw
}
