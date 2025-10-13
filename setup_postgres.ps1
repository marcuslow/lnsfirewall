# PostgreSQL Setup Script for Windows
# Run as Administrator

Write-Host "=== PostgreSQL Setup for LNS Firewall ===" -ForegroundColor Green

# Check if PostgreSQL is already installed
$pgPath = "C:\Program Files\PostgreSQL\16\bin\psql.exe"
if (Test-Path $pgPath) {
    Write-Host "✅ PostgreSQL is already installed" -ForegroundColor Green
} else {
    Write-Host "📦 Installing PostgreSQL via Chocolatey..." -ForegroundColor Yellow
    
    # Check if Chocolatey is installed
    if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Host "Installing Chocolatey first..." -ForegroundColor Yellow
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    }
    
    # Install PostgreSQL
    choco install postgresql16 -y --params '/Password:lnsFirewall2024!'
    
    Write-Host "✅ PostgreSQL installed" -ForegroundColor Green
    Write-Host "⚠️  Default password set to: lnsFirewall2024!" -ForegroundColor Yellow
}

# Add PostgreSQL to PATH if not already there
$pgBinPath = "C:\Program Files\PostgreSQL\16\bin"
if ($env:Path -notlike "*$pgBinPath*") {
    $env:Path += ";$pgBinPath"
    [Environment]::SetEnvironmentVariable("Path", $env:Path, [EnvironmentVariableTarget]::Machine)
    Write-Host "✅ Added PostgreSQL to PATH" -ForegroundColor Green
}

Write-Host ""
Write-Host "=== Next Steps ===" -ForegroundColor Green
Write-Host "1. PostgreSQL service should be running automatically"
Write-Host "2. Default credentials:"
Write-Host "   - Username: postgres"
Write-Host "   - Password: lnsFirewall2024!"
Write-Host "   - Port: 5432"
Write-Host ""
Write-Host "3. Run the database setup script:"
Write-Host "   python setup_postgres_db.py"
Write-Host ""

