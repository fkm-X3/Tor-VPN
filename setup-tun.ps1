# Setup script for TorVPN TUN driver
# Run this with Administrator privileges

$ErrorActionPreference = "Stop"
$WintunUrl = "https://www.wintun.net/builds/wintun-0.14.1.zip"
$WintunZip = "$env:TEMP\wintun.zip"
$WintunDir = "$env:TEMP\wintun"

Write-Host "=== TorVPN TUN Setup ===" -ForegroundColor Cyan
Write-Host ""

# Function to handle elevation via Windows Sudo
function Invoke-SudoElevation {
    # Check if sudo command exists in Windows
    $sudoExists = Get-Command sudo -ErrorAction SilentlyContinue

    if (-not $sudoExists) {
        Write-Host "[-] 'sudo' is not installed or enabled on this system." -ForegroundColor Yellow
        Write-Host "To enable Windows Sudo (Windows 11 Insider/Modern builds):" -ForegroundColor White
        Write-Host "  1. Open Settings -> System -> For developers." -ForegroundColor White
        Write-Host "  2. Toggle 'Enable sudo' to ON." -ForegroundColor White
        Write-Host "  3. Alternatively, run in an Admin PowerShell: " -ForegroundColor White
        Write-Host "     fscfg /enable-sudo" -ForegroundColor Magenta
        Write-Host ""
        
        $choice = Read-Host "Would you like to try continuing without admin rights? (y/N)"
        if ($choice -ne "y") { exit 1 }
        return
    }

    Write-Host "[!] 'sudo' detected." -ForegroundColor Cyan
    $sudoChoice = Read-Host "Would you like to relaunch this script using sudo? (Y/n)"
    if ($sudoChoice -eq "n") {
        $choice = Read-Host "Continue anyway without admin rights? (y/N)"
        if ($choice -ne "y") { exit 1 }
        return
    }

    Write-Host "Relaunching with sudo..." -ForegroundColor Green
    # Start a new powershell process using sudo, passing the current script path
    sudo powershell.exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
    exit
}

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "WARNING: Not running as Administrator." -ForegroundColor Yellow
    Write-Host "The TUN driver installation requires admin rights." -ForegroundColor Yellow
    Write-Host ""
    Invoke-SudoElevation
}

# Download wintun
Write-Host "Downloading wintun driver..." -ForegroundColor Green
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $WintunUrl -OutFile $WintunZip -UseBasicParsing
} catch {
    Write-Host "Download failed: $_" -ForegroundColor Red
    Write-Host "Please manually download from $WintunUrl" -ForegroundColor Yellow
    exit 1
}

# Extract
Write-Host "Extracting wintun..." -ForegroundColor Green
if (Test-Path $WintunDir) {
    Remove-Item -Recurse -Force $WintunDir
}
Expand-Archive -Path $WintunZip -DestinationPath $WintunDir

# Copy the correct architecture DLL to current directory
$arch = if ([Environment]::Is64BitProcess) { "amd64" } else { "x86" }
$dllSource = Join-Path $WintunDir "wintun\bin\$arch\wintun.dll"
$dllDest = Join-Path $PSScriptRoot "wintun.dll"

if (Test-Path $dllSource) {
    Copy-Item -Path $dllSource -Destination $dllDest -Force
    Write-Host "Copied wintun.dll to $dllDest" -ForegroundColor Green
} else {
    Write-Host "Could not find wintun.dll for architecture $arch" -ForegroundColor Red
    Write-Host "Available architectures:" -ForegroundColor Yellow
    Get-ChildItem (Join-Path $WintunDir "wintun\bin") -Directory | ForEach-Object { Write-Host "  - $($_.Name)" }
    exit 1
}

# Verify DLL
if (-not (Test-Path $dllDest)) {
    Write-Host "ERROR: wintun.dll not found after extraction!" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "wintun.dll ready at: $dllDest" -ForegroundColor Cyan

# Cleanup temp files
Remove-Item -Recurse -Force $WintunDir -ErrorAction SilentlyContinue
Remove-Item -Path $WintunZip -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== Setup Complete ===" -ForegroundColor Cyan
Write-Host "You can now build and run TorVPN: cargo run" -ForegroundColor Green
Write-Host ""
Write-Host "NOTE: The TUN interface will be created automatically when TorVPN runs." -ForegroundColor Yellow
Write-Host "If you encounter issues, make sure wintun.dll is in the same directory as the executable." -ForegroundColor Yellow