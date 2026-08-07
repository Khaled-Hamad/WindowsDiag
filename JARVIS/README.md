# Jarvis System

Jarvis System is a PowerShell diagnostic command center for this repository. It does not run intrusive collectors automatically; instead, it inventories available WindowsDiag tools, matches symptoms to the right package, and produces an operator-ready collection plan.

## Usage

Run from a PowerShell prompt at the repository root or from this folder:

```powershell
.\JARVIS\JarvisSystem.ps1 -Mode Inventory
.\JARVIS\JarvisSystem.ps1 -Profile Network -Symptom "lost static IP after reboot" -IncludeCommands
.\JARVIS\JarvisSystem.ps1 -Profile Security -Symptom "Kerberos logon failures" -OutputPath .\jarvis-plan.json -IncludeCommands
.\JARVIS\JarvisSystem.ps1 -Mode Interactive
```

## Modes

- `Inventory`: lists known diagnostic tools and whether the referenced files are present.
- `Analyze`: recommends tools for the selected profile and symptoms. This is the default mode.
- `Plan`: same recommendation engine as `Analyze`, with optional export through `-OutputPath`.
- `Interactive`: prompts for symptoms repeatedly and prints recommendations.

## Profiles

Supported profiles are `General`, `Network`, `Domain`, `Performance`, `Security`, and `Storage`. Jarvis combines the selected profile with symptom keywords to rank matching tools such as TSS, psSDP, CheckPCI, AD performance collection, authentication tracing, ChaseEvents, GetLogs, and MergeEvents.

## Safety

Jarvis only recommends collection steps. Review each referenced script or package README before running tools on a target system, and use an elevated shell when a recommendation indicates administrator rights are required.
