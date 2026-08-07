[CmdletBinding()]
param(
    [ValidateSet('Analyze', 'Inventory', 'Plan', 'Interactive')]
    [string]$Mode = 'Analyze',

    [string[]]$Symptom = @(),

    [ValidateSet('General', 'Network', 'Domain', 'Performance', 'Security', 'Storage')]
    [string]$Profile = 'General',

    [string]$OutputPath,

    [switch]$IncludeCommands
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Get-JarvisRepositoryRoot {
    $current = Split-Path -Parent $PSCommandPath

    while ($current -and -not (
        (Test-Path -LiteralPath (Join-Path $current 'README.md')) -and
        (Test-Path -LiteralPath (Join-Path $current 'LICENSE')) -and
        (Test-Path -LiteralPath (Join-Path $current 'ALL'))
    )) {
        $parent = Split-Path -Parent $current
        if ($parent -eq $current) {
            break
        }
        $current = $parent
    }

    return $current
}

function Test-JarvisAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Get-JarvisToolCatalog {
    $tools = @(
        [pscustomobject]@{
            Name = 'TSS all-in-one diagnostics'
            Area = 'General'
            RelativePath = 'ALL/TSS/tss_tools_v1.82.01.zip'
            UseCase = 'Collect broad Windows diagnostic traces, event logs, performance data, dumps, and SDP reports.'
            Signals = @('general', 'unknown', 'intermittent', 'trace', 'event', 'dump', 'diagnostic')
            Command = 'Extract ALL\TSS\tss_tools_v1.82.01.zip, then run tss.cmd with the switches that match the scenario.'
            RequiresAdmin = $true
            Notes = 'Best first collection package when the symptom is broad or not yet classified.'
        }
        [pscustomobject]@{
            Name = 'PowerShell SDP'
            Area = 'General'
            RelativePath = 'ALL/psSDP/psSDP-offline.zip'
            UseCase = 'Collect Support Diagnostic Package reports by specialty.'
            Signals = @('sdp', 'report', 'inventory', 'baseline', 'setup')
            Command = 'Extract ALL\psSDP\psSDP-offline.zip, then run .\Get-psSDP.ps1 Mini or another specialty.'
            RequiresAdmin = $true
            Notes = 'Useful for fast baseline reports and handoff bundles.'
        }
        [pscustomobject]@{
            Name = 'CheckPCI'
            Area = 'Network'
            RelativePath = 'NET/CheckPCI/CheckPCI.zip'
            UseCase = 'Investigate lost static IP addresses, missing NIC drivers, and PCI/NIC state changes.'
            Signals = @('network', 'nic', 'pci', 'ip', 'driver', 'adapter')
            Command = 'Extract NET\CheckPCI\CheckPCI.zip, then run .\CheckPCI.ps1 with Before or After collection mode.'
            RequiresAdmin = $true
            Notes = 'Run before and after reboot when tracking adapter configuration changes.'
        }
        [pscustomobject]@{
            Name = 'Active Directory Performance'
            Area = 'Domain'
            RelativePath = 'Windows_DS/AD_PERF/ADPerfDataCollection.ps1'
            UseCase = 'Collect Active Directory domain controller performance diagnostics.'
            Signals = @('active directory', 'domain', 'dc', 'ldap', 'replication', 'logon', 'auth')
            Command = 'Run Windows_DS\AD_PERF\ADPerfDataCollection.ps1 from an elevated PowerShell prompt on the target system.'
            RequiresAdmin = $true
            Notes = 'Use for domain controller health, authentication, and directory performance scenarios.'
        }
        [pscustomobject]@{
            Name = 'Authentication tracing'
            Area = 'Security'
            RelativePath = 'Windows_DS/AUTH/start-auth.txt'
            UseCase = 'Enable and stop authentication-focused tracing and log capture.'
            Signals = @('auth', 'kerberos', 'ntlm', 'logon', 'lsa', 'schannel', 'credential')
            Command = 'Copy Windows_DS\AUTH\start-auth.txt and stop-auth.txt to the target, rename to .cmd, then run start and stop around repro.'
            RequiresAdmin = $true
            Notes = 'Review the text files before running because they enable registry-backed tracing.'
        }
        [pscustomobject]@{
            Name = 'Smart card and certificate tracing'
            Area = 'Security'
            RelativePath = 'Windows_DS/PKI_Scard/start-sc.txt'
            UseCase = 'Collect smart card, certificate, and authentication diagnostics.'
            Signals = @('smart card', 'certificate', 'pki', 'scard', 'cert', 'tls')
            Command = 'Copy Windows_DS\PKI_Scard\start-sc.txt and stop-sc.txt to the target, rename to .cmd, then run start and stop around repro.'
            RequiresAdmin = $true
            Notes = 'Use for certificate-backed sign-in, smart card, and PKI issues.'
        }
        [pscustomobject]@{
            Name = 'ChaseEvents'
            Area = 'Performance'
            RelativePath = 'SHA/ChaseEvents/ChaseEvents.ps1'
            UseCase = 'Find recurring events over a selected period and format.'
            Signals = @('event', 'cluster', 'history', 'recurring', 'critical', 'warning')
            Command = 'Run SHA\ChaseEvents\ChaseEvents.ps1 with EventId, EventLevel, Days, and Format parameters.'
            RequiresAdmin = $false
            Notes = 'Good for rapid event-log triage before deeper tracing.'
        }
        [pscustomobject]@{
            Name = 'GetLogs'
            Area = 'General'
            RelativePath = 'SHA/GetLogs/GetLogs.zip'
            UseCase = 'Collect basic diagnostic data from Windows systems.'
            Signals = @('logs', 'basic', 'quick', 'remote', 'computername')
            Command = 'Extract SHA\GetLogs\GetLogs.zip, then run GetLogs.ps1 locally or with -ComputerName.'
            RequiresAdmin = $true
            Notes = 'Use when a compact basic log bundle is sufficient.'
        }
        [pscustomobject]@{
            Name = 'MergeEvents'
            Area = 'Performance'
            RelativePath = 'SHA/MergeEvents/MergeEvents.zip'
            UseCase = 'Merge event data for easier timeline review.'
            Signals = @('merge', 'timeline', 'events', 'correlate')
            Command = 'Extract SHA\MergeEvents\MergeEvents.zip and follow SHA\MergeEvents\README.md.'
            RequiresAdmin = $false
            Notes = 'Helpful after collecting multiple event sources.'
        }
    )

    return $tools
}

function Resolve-JarvisToolState {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Tools,
        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot
    )

    foreach ($tool in $Tools) {
        $fullPath = Join-Path $RepositoryRoot $tool.RelativePath
        $tool | Add-Member -NotePropertyName FullPath -NotePropertyValue $fullPath -Force
        $tool | Add-Member -NotePropertyName Available -NotePropertyValue (Test-Path -LiteralPath $fullPath) -Force
        $tool
    }
}

function Find-JarvisMatches {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Tools,
        [string[]]$SymptomText,
        [string]$ProfileName
    )

    $terms = @()
    foreach ($item in $SymptomText) {
        if ($item) {
            $terms += $item.ToLowerInvariant()
        }
    }
    if ($ProfileName -and $ProfileName -ne 'General') {
        $terms += $ProfileName.ToLowerInvariant()
    }

    $scored = foreach ($tool in $Tools) {
        $score = 0
        if ($ProfileName -eq 'General' -or $tool.Area -eq $ProfileName) {
            $score += 2
        }

        foreach ($term in $terms) {
            foreach ($signal in $tool.Signals) {
                if ($term -like "*$($signal.ToLowerInvariant())*" -or $signal.ToLowerInvariant() -like "*$term*") {
                    $score += 4
                }
            }
            if ($tool.Name.ToLowerInvariant() -like "*$term*" -or $tool.UseCase.ToLowerInvariant() -like "*$term*") {
                $score += 2
            }
        }

        if ($score -gt 0) {
            [pscustomobject]@{
                Score = $score
                Tool = $tool
            }
        }
    }

    $matchedTools = @($scored | Sort-Object -Property Score -Descending | Select-Object -First 5)
    if ($matchedTools.Count -eq 0) {
        $matchedTools = @($Tools | Where-Object { $_.Area -eq 'General' } | Select-Object -First 3 | ForEach-Object {
            [pscustomobject]@{ Score = 1; Tool = $_ }
        })
    }

    return $matchedTools
}

function New-JarvisPlan {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Matches,
        [Parameter(Mandatory = $true)]
        [string]$ProfileName,
        [string[]]$SymptomText,
        [switch]$WithCommands
    )

    $steps = New-Object System.Collections.ArrayList
    [void]$steps.Add([pscustomobject]@{
        Phase = 'Prepare'
        Action = 'Run from an elevated shell when collection requires administrator rights.'
        Command = $null
    })
    [void]$steps.Add([pscustomobject]@{
        Phase = 'Triage'
        Action = 'Confirm symptom scope, affected machines, timing, recent changes, and reproduction steps.'
        Command = $null
    })

    foreach ($match in $Matches) {
        $tool = $match.Tool
        [void]$steps.Add([pscustomobject]@{
            Phase = 'Collect'
            Action = "Use $($tool.Name): $($tool.UseCase)"
            Command = $(if ($WithCommands) { $tool.Command } else { $null })
        })
    }

    [void]$steps.Add([pscustomobject]@{
        Phase = 'Review'
        Action = 'Package outputs with timestamps, affected host names, and notes from the reproduction window.'
        Command = $null
    })

    return [pscustomobject]@{
        GeneratedAt = (Get-Date).ToString('s')
        Profile = $ProfileName
        Symptoms = $SymptomText
        IsAdministrator = (Test-JarvisAdministrator)
        Recommendations = @($Matches | ForEach-Object {
            [pscustomobject]@{
                Name = $_.Tool.Name
                Area = $_.Tool.Area
                Score = $_.Score
                Available = $_.Tool.Available
                Path = $_.Tool.RelativePath
                RequiresAdmin = $_.Tool.RequiresAdmin
                UseCase = $_.Tool.UseCase
                Notes = $_.Tool.Notes
                Command = $(if ($WithCommands) { $_.Tool.Command } else { $null })
            }
        })
        Steps = @($steps)
    }
}

function Write-JarvisPlan {
    param([Parameter(Mandatory = $true)] [object]$Plan)

    Write-Host "Jarvis diagnostic profile: $($Plan.Profile)" -ForegroundColor Cyan
    if ($Plan.Symptoms -and $Plan.Symptoms.Count -gt 0) {
        Write-Host "Symptoms: $($Plan.Symptoms -join '; ')"
    }
    Write-Host "Administrator: $($Plan.IsAdministrator)"
    Write-Host ''
    Write-Host 'Recommended tools:' -ForegroundColor Cyan

    foreach ($item in $Plan.Recommendations) {
        $status = if ($item.Available) { 'available' } else { 'missing' }
        Write-Host ("- {0} [{1}, score {2}, {3}]" -f $item.Name, $item.Area, $item.Score, $status)
        Write-Host "  $($item.UseCase)"
        if ($item.Command) {
            Write-Host "  Command: $($item.Command)"
        }
        Write-Host "  Note: $($item.Notes)"
    }

    Write-Host ''
    Write-Host 'Plan:' -ForegroundColor Cyan
    foreach ($step in $Plan.Steps) {
        Write-Host ("- {0}: {1}" -f $step.Phase, $step.Action)
        if ($step.Command) {
            Write-Host "  $($step.Command)"
        }
    }
}

function Export-JarvisPlan {
    param(
        [Parameter(Mandatory = $true)] [object]$Plan,
        [Parameter(Mandatory = $true)] [string]$Path
    )

    $extension = [IO.Path]::GetExtension($Path).ToLowerInvariant()
    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    if ($extension -eq '.json') {
        $Plan | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Path -Encoding UTF8
    }
    else {
        $lines = New-Object System.Collections.ArrayList
        [void]$lines.Add("Jarvis diagnostic profile: $($Plan.Profile)")
        [void]$lines.Add("Generated: $($Plan.GeneratedAt)")
        [void]$lines.Add("Symptoms: $($Plan.Symptoms -join '; ')")
        [void]$lines.Add('')
        [void]$lines.Add('Recommended tools:')
        foreach ($item in $Plan.Recommendations) {
            [void]$lines.Add("- $($item.Name) [$($item.Area)]")
            [void]$lines.Add("  $($item.UseCase)")
            if ($item.Command) {
                [void]$lines.Add("  Command: $($item.Command)")
            }
            [void]$lines.Add("  Note: $($item.Notes)")
        }
        [void]$lines.Add('')
        [void]$lines.Add('Plan:')
        foreach ($step in $Plan.Steps) {
            [void]$lines.Add("- $($step.Phase): $($step.Action)")
            if ($step.Command) {
                [void]$lines.Add("  $($step.Command)")
            }
        }
        $lines | Set-Content -LiteralPath $Path -Encoding UTF8
    }
}

function Start-JarvisInteractive {
    param(
        [Parameter(Mandatory = $true)] [object[]]$Tools,
        [switch]$WithCommands
    )

    Write-Host 'Jarvis interactive diagnostic assistant. Type quit to exit.' -ForegroundColor Cyan
    while ($true) {
        $inputText = Read-Host 'Describe the symptom'
        if ($inputText -match '^(quit|exit)$') {
            break
        }
        $profileText = Read-Host 'Profile (General, Network, Domain, Performance, Security, Storage)'
        if (-not $profileText) {
            $profileText = 'General'
        }
        if (@('General', 'Network', 'Domain', 'Performance', 'Security', 'Storage') -notcontains $profileText) {
            Write-Warning 'Unknown profile; using General.'
            $profileText = 'General'
        }
        $matchedTools = Find-JarvisMatches -Tools $Tools -SymptomText @($inputText) -ProfileName $profileText
        $plan = New-JarvisPlan -Matches $matchedTools -ProfileName $profileText -SymptomText @($inputText) -WithCommands:$WithCommands
        Write-JarvisPlan -Plan $plan
    }
}

$repositoryRoot = Get-JarvisRepositoryRoot
$catalog = @(Resolve-JarvisToolState -Tools (Get-JarvisToolCatalog) -RepositoryRoot $repositoryRoot)

switch ($Mode) {
    'Inventory' {
        $catalog | Sort-Object Area, Name | Select-Object Name, Area, Available, RequiresAdmin, RelativePath, UseCase | Format-Table -AutoSize
    }
    'Interactive' {
        Start-JarvisInteractive -Tools $catalog -WithCommands:$IncludeCommands
    }
    default {
        $symptomsForPlan = @($Symptom)
        if ($symptomsForPlan.Count -eq 0) {
            $symptomsForPlan = @($Profile)
        }
        $matchedTools = Find-JarvisMatches -Tools $catalog -SymptomText $symptomsForPlan -ProfileName $Profile
        $plan = New-JarvisPlan -Matches $matchedTools -ProfileName $Profile -SymptomText $symptomsForPlan -WithCommands:$IncludeCommands
        Write-JarvisPlan -Plan $plan
        if ($OutputPath) {
            Export-JarvisPlan -Plan $plan -Path $OutputPath
            Write-Host "`nSaved plan to $OutputPath" -ForegroundColor Green
        }
    }
}
