# Install build prerequisites on Windows.
#
# This script assumes you have one of:
#   - vcpkg (preferred)
#   - chocolatey
#
# Run from an admin PowerShell.

$ErrorActionPreference = "Stop"

if (Get-Command vcpkg -ErrorAction SilentlyContinue) {
    Write-Host "Using vcpkg to install sqlite3 and openssl..."
    vcpkg install sqlite3:x64-windows openssl:x64-windows
    Write-Host ""
    Write-Host "Configure cmake with:"
    Write-Host "  cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=<vcpkg-root>/scripts/buildsystems/vcpkg.cmake"
} elseif (Get-Command choco -ErrorAction SilentlyContinue) {
    Write-Host "Using Chocolatey..."
    choco install -y cmake sqlite openssl
} else {
    Write-Host "Install vcpkg (https://github.com/microsoft/vcpkg) or Chocolatey first." -ForegroundColor Yellow
    exit 1
}
