<# 
  vTPM2 removal script.
  Stops and removes the vTPM2 Windows service.

  Safety rules:
  - Requires administrator elevation.
  - Does NOT modify firmware, ACPI tables, or boot configuration.
  - Preserves TPM state under %PROGRAMDATA%\vTPM2\state by default (use -PurgeState to delete).
#>
param(
  [string]$InstallDir = "${env:PROGRAMDATA}\vTPM2",
  [string]$ServiceName = "vTPM2",
  [switch]$PurgeState
)

$ErrorActionPreference = "Stop"

$isAdmin = -not ([Security.Principal.WindowsPrincipal]
  [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
  Write-Error "Administrator elevation is required. Re-run this script as Administrator."
  exit 1
}

Write-Host "vTPM2 removal"

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
  if ($svc.Status -eq 'Running') {
    Write-Host "Stopping service $ServiceName..."
    Stop-Service -Name $ServiceName -Force
  }
  sc.exe delete $ServiceName | Out-Null
  Write-Host "Service $ServiceName removed."
} else {
  Write-Host "Service $ServiceName not found (already removed or never installed)."
}

if ($PurgeState) {
  $stateDir = Join-Path $InstallDir "state"
  $snapshot = Join-Path $InstallDir "state" "tpm-state.json"
  if (Test-Path $snapshot) {
    Write-Host "Purging TPM state snapshot: $snapshot"
    Remove-Item -Path $snapshot -Force
  }
  Write-Host "State directory retained: $stateDir (manual backup recommended before purge)"
} else {
  Write-Host "TPM state preserved under $InstallDir\state"
}

Write-Host "Removal complete."
