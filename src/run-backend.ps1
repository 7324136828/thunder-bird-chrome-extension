<#
.SYNOPSIS
  Start the mail backend (mail-backend), default http://127.0.0.1:48101.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File src\run-backend.ps1
  powershell -ExecutionPolicy Bypass -File src\run-backend.ps1 -Port 48200
  powershell -ExecutionPolicy Bypass -File src\run-backend.ps1 -Addr 127.0.0.1:48101
.NOTES
  Keep the window open while you use the extension; press Ctrl+C to stop it.
  Mailbox passwords are kept in memory only: stopping the backend locks every account.
#>
param(
  [int]$Port = 0,
  [string]$Addr = '',
  [switch]$DebugBuild
)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

$backendArgs = @()
if ($Addr -ne '') { $backendArgs += @('--addr', $Addr) }
if ($Port -gt 0) { $backendArgs += @('--port', "$Port") }

$cargo = Get-Command cargo -ErrorAction SilentlyContinue
$exe = Join-Path $PSScriptRoot 'target\release\mail-backend.exe'

if ($cargo) {
  Write-Host 'Building and starting mail-backend (the first build takes a few minutes)...'
  $profileArgs = @('--release')
  if ($DebugBuild) { $profileArgs = @() }
  & cargo run @profileArgs -p mail-backend -- @backendArgs
  exit $LASTEXITCODE
} elseif (Test-Path -LiteralPath $exe) {
  Write-Host 'cargo not found - starting the previously built mail-backend.exe'
  & $exe @backendArgs
  exit $LASTEXITCODE
} else {
  Write-Host ''
  Write-Host 'Rust is not installed, so mail-backend cannot be built.'
  Write-Host ' 1. Install Rust from https://rustup.rs (accept the defaults)'
  Write-Host ' 2. Open a NEW terminal and run this script again.'
  Write-Host ''
  Write-Host 'The mail extension needs this backend for every mailbox operation.'
  exit 1
}
