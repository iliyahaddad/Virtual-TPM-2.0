<# 
  vTPM2 installer (PowerShell).
  Installs the vTPM2 Windows service hosting the software TPM 2.0 engine.

  Safety rules (enforced):
  - Requires administrator elevation.
  - Does NOT modify firmware, ACPI tables, or boot configuration.
  - Does NOT enable Windows Test Mode.
  - Does NOT disable driver signature enforcement or Secure Boot.
  - Does NOT touch BitLocker.
  - Installs a user-mode service only; no kernel driver is loaded.
#>
param(
  [string]$InstallDir = "${env:PROGRAMDATA}\vTPM2",
  [string]$ServiceName = "vTPM2",
  [string]$DisplayName = "vTPM2 Software TPM 2.0",
  [string]$BinarySource = (Join-Path $PSScriptRoot "..\src\service\vtpmservice.exe")
)

$ErrorActionPreference = "Stop"

# --- Administrator consent -------------------------------------------------
$isAdmin = -not ([Security.Principal.WindowsPrincipal]
  [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
  Write-Error "Administrator elevation is required. Re-run this script as Administrator."
  exit 1
}

Write-Host "vTPM2 installer"
Write-Host "  InstallDir : $InstallDir"
Write-Host "  Service    : $ServiceName"

# --- Confirmation ----------------------------------------------------------
$confirm = Read-Host "Proceed with installation? (y/N)"
if ($confirm -ne "y" -and $confirm -ne "Y") {
  Write-Host "Installation cancelled."
  exit 0
}

# --- Install files ---------------------------------------------------------
if (-not (Test-Path $BinarySource)) {
  Write-Error "Service binary not found: $BinarySource. Build it first (see BUILD.md)."
  exit 1
}
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item -Path $BinarySource -Destination (Join-Path $InstallDir "vtpmservice.exe") -Force

# --- State directory -------------------------------------------------------
$stateDir = Join-Path $InstallDir "state"
New-Item -ItemType Directory -Path $stateDir -Force | Out-Null

# --- Install service (user-mode only; no kernel driver) --------------------
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
  Write-Host "Service $ServiceName already exists; removing it first."
  if ($existing.Status -eq 'Running') { Stop-Service -Name $ServiceName }
  sc.exe delete $ServiceName | Out-Null
}

$binPath = Join-Path $InstallDir "vtpmservice.exe"
sc.exe create $ServiceName binPath= "`"$binPath`" " start= demand DisplayName= "`"$DisplayName`""
if ($LASTEXITCODE -ne 0) {
  Write-Error "sc.exe create failed."
  exit 1
}

sc.exe description $ServiceName "vTPM2 software TPM 2.0 engine (user-mode service). No hardware TPM; not recognized by Windows Security as a platform TPM." | Out-Null

Write-Host "Installed. Start with: sc start $ServiceName"
Write-Host "Dashboard: http://127.0.0.1:8082  (once the service is running)"
Write-Host "Remove with: .\remove.ps1"
