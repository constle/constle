# install.ps1 — one-line installer for constle (Windows)
#
# Usage (what users run):
#   iwr -useb https://constle.dev/install.ps1 | iex
#
#   iwr  = Invoke-WebRequest  (downloads the script text)
#   -useb = -UseBasicParsing  (doesn't need Internet Explorer's COM object,
#                              works on Windows Server Core and fresh installs)
#   iex  = Invoke-Expression  (executes the downloaded text as PowerShell)
#
# What this script does, step by step:
#   1. Enforce TLS 1.2 (required for GitHub; old PowerShell defaults to TLS 1.0)
#   2. Detect CPU architecture
#   3. Fetch the latest release version from the GitHub API
#   4. Download the correct .zip archive
#   5. Extract the binary
#   6. Install to %LOCALAPPDATA%\Programs\constle (no admin needed)
#   7. Add the install directory to the user's PATH if it's not already there

#Requires -Version 5.1  # Minimum PowerShell version (ships with Windows 10)

$ErrorActionPreference = 'Stop'  # Treat all errors as terminating.
                                  # Equivalent to set -e in bash.

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
$Repo       = "constle/constle"
$BinaryName = "constle.exe"

# Install here — no administrator rights needed because LOCALAPPDATA is the
# current user's own folder (e.g. C:\Users\yourname\AppData\Local\Programs\constle)
$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\constle"

# ---------------------------------------------------------------------------
# Pretty output helpers
# ---------------------------------------------------------------------------
function Write-Step { param($msg) Write-Host "  " -NoNewline; Write-Host "→ " -NoNewline -ForegroundColor Blue;  Write-Host $msg }
function Write-Ok   { param($msg) Write-Host "  " -NoNewline; Write-Host "✓ " -NoNewline -ForegroundColor Green; Write-Host $msg }
function Write-Fail { param($msg) Write-Host "`nerror: $msg`n" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "constle installer" -ForegroundColor White
Write-Host ""

# ---------------------------------------------------------------------------
# Step 1: Enforce TLS 1.2
#
# PowerShell 5.1 on Windows 10 defaults to TLS 1.0 for web requests, which
# GitHub no longer accepts.  This line forces TLS 1.2 for the duration of
# this script.  PowerShell 7+ uses TLS 1.2/1.3 by default and ignores this.
# ---------------------------------------------------------------------------
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ---------------------------------------------------------------------------
# Step 2: Detect architecture
#
# $env:PROCESSOR_ARCHITECTURE is set by Windows for the current process.
# Values:  AMD64 (64-bit Intel/AMD), ARM64 (64-bit ARM), x86 (32-bit Intel)
#
# Note: if you run a 32-bit PowerShell on a 64-bit machine, this env var
# shows x86.  We use [System.Runtime.InteropServices.RuntimeInformation] as
# a more reliable fallback.
# ---------------------------------------------------------------------------
$RawArch = $env:PROCESSOR_ARCHITECTURE
if ($RawArch -eq 'x86') {
    # We might be a 32-bit process on a 64-bit OS.  Check the real OS arch.
    $OsArch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    if ($OsArch -eq 'X64')  { $RawArch = 'AMD64' }
    if ($OsArch -eq 'Arm64') { $RawArch = 'ARM64' }
}

$Arch = switch ($RawArch) {
    'AMD64' { 'amd64' }
    'ARM64' { 'arm64' }
    default  { Write-Fail "unsupported architecture: $RawArch" }
}

Write-Step "arch: $Arch"

# ---------------------------------------------------------------------------
# Step 3: Fetch the latest release version from GitHub API
#
# Invoke-RestMethod downloads the URL and automatically parses the JSON
# response body into a PowerShell object.  So $Release.tag_name gives us
# the "tag_name" field from the JSON without any manual parsing.
# ---------------------------------------------------------------------------
Write-Step "fetching latest release from GitHub..."

$ApiUrl = "https://api.github.com/repos/$Repo/releases/latest"
try {
    $Release = Invoke-RestMethod -Uri $ApiUrl -UseBasicParsing
} catch {
    Write-Fail "could not reach GitHub API: $_`nCheck your internet connection or visit: https://github.com/$Repo/releases"
}

$Version = $Release.tag_name
if (-not $Version) {
    Write-Fail "could not determine latest release version"
}

Write-Ok "latest version: $Version"

# ---------------------------------------------------------------------------
# Step 4: Construct the download URL
#
# GoReleaser names archives with the template:
#   constle_{{ .Version }}_{{ .Os }}_{{ .Arch }}.zip
#
# {{.Version}} strips the leading "v" from the tag.
# Tag "v0.5.0" → archive "constle_0.5.0_windows_amd64.zip"
# but the GitHub URL path still uses the full tag: /download/v0.5.0/constle_0.5.0...
# ---------------------------------------------------------------------------
$VersionNoV = $Version.TrimStart('v')   # "v0.5.0" → "0.5.0"
$Archive    = "constle_${VersionNoV}_windows_${Arch}.zip"
$Url        = "https://github.com/$Repo/releases/download/$Version/$Archive"

Write-Step "downloading $Archive..."

# ---------------------------------------------------------------------------
# Step 5: Download to a temporary directory
#
# [System.IO.Path]::GetTempPath()  — e.g. C:\Users\yourname\AppData\Local\Temp\
# GetRandomFileName()               — e.g. "constle-a3bx9q"
# ---------------------------------------------------------------------------
$TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) "constle-install-$(([System.IO.Path]::GetRandomFileName()).Replace('.',''))"
New-Item -ItemType Directory -Path $TmpDir | Out-Null

$ArchivePath = Join-Path $TmpDir $Archive

try {
    Invoke-WebRequest -Uri $Url -OutFile $ArchivePath -UseBasicParsing
} catch {
    Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
    Write-Fail "download failed: $_`nURL: $Url"
}

# ---------------------------------------------------------------------------
# Step 6: Extract the zip archive
#
# Expand-Archive is built into PowerShell 5.1+ and understands .zip files
# natively.  -Force overwrites existing files in the destination.
# ---------------------------------------------------------------------------
Write-Step "extracting..."
Expand-Archive -Path $ArchivePath -DestinationPath $TmpDir -Force

# Find the binary — handle both flat archive and subdirectory layouts.
$BinaryPath = Get-ChildItem -Path $TmpDir -Filter $BinaryName -Recurse | Select-Object -First 1

if (-not $BinaryPath) {
    Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
    Write-Fail "binary '$BinaryName' not found in archive — please report at https://github.com/$Repo/issues"
}

# ---------------------------------------------------------------------------
# Step 7: Install
#
# Create the install directory if it doesn't exist (-Force does nothing if
# it already exists, unlike mkdir which would error).
# Then move the binary there.
# ---------------------------------------------------------------------------
Write-Step "installing to $InstallDir..."
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Move-Item -Path $BinaryPath.FullName -Destination (Join-Path $InstallDir $BinaryName) -Force

# ---------------------------------------------------------------------------
# Step 8: Add to the user PATH (if not already present)
#
# There are two levels of PATH on Windows:
#   Machine — HKLM, applies to all users, requires admin to change
#   User    — HKCU, applies only to the current user, no admin needed
#
# We modify the User-level PATH so constle is available in new shells without
# needing administrator rights.
#
# [System.Environment]::GetEnvironmentVariable(name, target) reads from the
# registry (persistent), not from the current process $env:PATH (ephemeral).
# We also update $env:PATH in the current process so constle works immediately
# in this same terminal session.
# ---------------------------------------------------------------------------
$UserPath = [System.Environment]::GetEnvironmentVariable('PATH', 'User')

if ($UserPath -notlike "*$InstallDir*") {
    $NewPath = if ($UserPath) { "$UserPath;$InstallDir" } else { $InstallDir }

    [System.Environment]::SetEnvironmentVariable('PATH', $NewPath, 'User')
    $env:PATH = "$env:PATH;$InstallDir"   # update current session too

    Write-Ok "added $InstallDir to user PATH"
    Write-Host "    (restart other terminals for PATH to take effect)"
} else {
    Write-Ok "$InstallDir already in PATH"
}

# ---------------------------------------------------------------------------
# Cleanup temporary files
# ---------------------------------------------------------------------------
Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# Done!
# ---------------------------------------------------------------------------
Write-Host ""
Write-Ok "constle $Version installed!"
Write-Host ""
Write-Host "  Get started:"
Write-Host "    constle --help"
Write-Host "    constle validate agent.yaml"
Write-Host ""
