<#
Creates a pfSense client bundle ZIP with the exact files needed for deployment.

Included in the ZIP (with folder structure):
  pfsense-client-bundle/
    client/pfsense_client.py
    client/psutil_stub.py
    config/client_config.yaml
    setup_client.sh

Usage (PowerShell):
  pwsh -File .\make_client_bundle.ps1
  # or
  powershell -ExecutionPolicy Bypass -File .\make_client_bundle.ps1 -OutputDir dist -BundleName pfsense-client-bundle

Outputs:
  .\dist\pfsense-client-bundle-YYYYMMDD-HHMMSS.zip (by default)
#>
param(
  [string]$OutputDir = "dist",
  [string]$BundleName = "pfsense-client-bundle"
)

$ErrorActionPreference = 'Stop'

function New-DirSafe([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path | Out-Null
  }
}

# Resolve repo root as the script directory
$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $RepoRoot

$Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$StagingRoot = Join-Path $RepoRoot "${OutputDir}\${BundleName}"
$ZipOutDir   = Join-Path $RepoRoot $OutputDir
$ZipPath     = Join-Path $ZipOutDir ("{0}-{1}.zip" -f $BundleName, $Timestamp)

# Files to include (source -> relative path inside bundle)
$Files = @(
  @{ Src = "client/pfsense_client.py";      Dest = "client/pfsense_client.py" },
  @{ Src = "client/psutil_stub.py";         Dest = "client/psutil_stub.py" },
  @{ Src = "config/client_config.yaml";     Dest = "config/client_config.yaml" },
  @{ Src = "setup_client.sh";               Dest = "setup_client.sh" },
  @{ Src = "restart_client.sh";             Dest = "restart_client.sh" }
)

Write-Host "Creating bundle staging at: $StagingRoot" -ForegroundColor Cyan
# Clean staging if exists
if (Test-Path -LiteralPath $StagingRoot) { Remove-Item -LiteralPath $StagingRoot -Recurse -Force }
New-DirSafe $StagingRoot

# Copy files with structure
foreach ($f in $Files) {
  $src = Join-Path $RepoRoot $f.Src
  $dst = Join-Path $StagingRoot $f.Dest
  $dstDir = Split-Path -Parent $dst
  if (-not (Test-Path -LiteralPath $src)) {
    throw "Missing required file: $($f.Src)"
  }
  New-DirSafe $dstDir
  Copy-Item -LiteralPath $src -Destination $dst -Force
}

# Ensure output dir
New-DirSafe $ZipOutDir

# Create zip
if (Test-Path -LiteralPath $ZipPath) { Remove-Item -LiteralPath $ZipPath -Force }
Write-Host "Compressing to: $ZipPath" -ForegroundColor Cyan
Compress-Archive -Path (Join-Path $StagingRoot '*') -DestinationPath $ZipPath -Force

# Show summary
Write-Host "Bundle created successfully:" -ForegroundColor Green
Write-Host "  $ZipPath"
Write-Host "Contains:" -ForegroundColor Green
Get-ChildItem -Recurse -File $StagingRoot | ForEach-Object {
  $rel = $_.FullName.Substring($StagingRoot.Length + 1)
  Write-Host "  - $rel"
}

Write-Host "" 
Write-Host "Next steps (pfSense):" -ForegroundColor Yellow
Write-Host "  1) scp `"$ZipPath`" root@<pfsense-ip>:/root/" 
Write-Host "  2) ssh root@<pfsense-ip>" 
Write-Host "  3) cd /root && unzip $(Split-Path -Leaf $ZipPath)" 
Write-Host "  4) cd ${BundleName} && ls -la"
Write-Host "  5) Edit config/client_config.yaml (set hq_url and client_name)" 
Write-Host "  6) Install dependencies and set up service with your existing scripts if needed" 

