$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
if (-not $ProjectRoot) { $ProjectRoot = Get-Location }

Set-Location (Join-Path $ProjectRoot "tor-tun")

Write-Host "==> Building tor-tun (release)..." -ForegroundColor Cyan
cargo build --release
if (-not $?) { throw "cargo build failed" }

$BinaryDir = Join-Path $ProjectRoot "tor-tun\target\release"
$DllPath = Join-Path $BinaryDir "wintun.dll"

if (Test-Path $DllPath) {
    Write-Host "==> wintun.dll already present at $DllPath" -ForegroundColor Green
} else {
    Write-Host "==> Downloading wintun.dll from wintun.net..." -ForegroundColor Cyan
    $Url = "https://www.wintun.net/builds/wintun-0.14.1.zip"
    $ZipPath = Join-Path $env:TEMP "wintun-0.14.1.zip"
    $ExtractPath = Join-Path $env:TEMP "wintun-0.14.1"

    try {
        Invoke-WebRequest -Uri $Url -OutFile $ZipPath -UseBasicParsing
        Expand-Archive -Path $ZipPath -DestinationPath $ExtractPath -Force
        $DllSource = Join-Path $ExtractPath "wintun\bin\amd64\wintun.dll"
        if (-not (Test-Path $DllSource)) {
            throw "wintun.dll not found in the archive (expected at wintun\bin\amd64\wintun.dll)"
        }
        Copy-Item -Path $DllSource -Destination $DllPath
        Write-Host "==> wintun.dll placed at $DllPath" -ForegroundColor Green
    } finally {
        if (Test-Path $ZipPath)    { Remove-Item $ZipPath -Force }
        if (Test-Path $ExtractPath) { Remove-Item $ExtractPath -Recurse -Force }
    }
}

Write-Host "==> Setup complete. Run the binary as Administrator:" -ForegroundColor Yellow
Write-Host "    $BinaryDir\tor-tun.exe" -ForegroundColor Cyan