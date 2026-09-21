# install.ps1 -- one-line installer for constle (Windows)
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
#   4. Work out the download URL
#   5. Download the .zip archive to a temporary directory
#   6. Verify it against the release's checksums.txt, and verify cosign's
#      signature over that file; both have to pass
#   7. Extract the binary
#   8. Install to %LOCALAPPDATA%\Programs\constle (no admin needed)
#   9. Add the install directory to the user's PATH if it's not already there
#
# Environment variables:
#   CONSTLE_INSTALL_DIR         where to put the binary
#                               (default %LOCALAPPDATA%\Programs\constle)
#   CONSTLE_ALLOW_UNSIGNED      set to 1 to install a release whose signature
#                               could not be checked at all. It never weakens
#                               the checksum, and never forgives a signature
#                               that was checked and failed.
#   CONSTLE_INSTALL_BASE_URL    release download host (default https://github.com)
#   CONSTLE_INSTALL_API_URL     release metadata host (default https://api.github.com)
#
# CONSTLE_REQUIRE_SIGNATURE is still recognised, but requiring the signature is
# now the default, so setting it changes nothing - and setting it to 0 does not
# bring the old lenient behaviour back.
#
# The last two exist so that this script can be pointed at a mirror, and so
# that its regression test can serve a fake release from a local HTTP server.
# Be clear about what they are: they choose WHERE the bytes come from, which
# means whoever sets them chooses the publisher. A host that serves a tampered
# archive together with a checksums.txt that agrees with it passes the checksum
# comparison below, because the two files agree with each other and with
# nothing else. What an override cannot reach is the pinned signing identity,
# which is a literal in this file. That is why they are held to HTTPS, and why
# nothing here can switch the checks off.

# Minimum PowerShell version (ships with Windows 10). The comment is on its own
# line: a #Requires statement has to be the only thing on its line.
#Requires -Version 5.1

$ErrorActionPreference = 'Stop'  # Treat all errors as terminating.
                                  # Equivalent to set -e in bash.

# Windows PowerShell 5.1 redraws a progress bar on every chunk of every
# Invoke-WebRequest download, which costs far more time than the download
# itself. Turning it off is worth roughly an order of magnitude here.
# Saved and restored, because under `iwr | iex` this script runs in the
# caller's own session and must not leave their preferences changed.
$PrevProgressPreference = $ProgressPreference
$ProgressPreference     = 'SilentlyContinue'

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
$Repo       = "constle/constle"
$BinaryName = "constle.exe"

# Where releases are fetched from. Overridable for mirrors and for the
# regression test; see the note in the header about what this does and does
# not change.
$BaseUrl    = if ($env:CONSTLE_INSTALL_BASE_URL) { $env:CONSTLE_INSTALL_BASE_URL } else { "https://github.com" }
$ApiBaseUrl = if ($env:CONSTLE_INSTALL_API_URL)  { $env:CONSTLE_INSTALL_API_URL }  else { "https://api.github.com" }

# Whether a signature that could not be checked AT ALL is survivable. The
# default is no, and that is the whole point of this script.
#
# checksums.txt travels with the archive: same release, same host, same
# connection. Against anyone who can write to that release - a stolen token, a
# compromised workflow - the checksum agrees with the archive because the same
# hand wrote both. The signature is the only link here that such an attacker
# cannot forge, so an install that skipped it got a corruption check and no
# security check at all.
#
# CONSTLE_ALLOW_UNSIGNED=1 says "I know, do it anyway", and reaches exactly the
# two cases where there was nothing to check. A signature that IS present and
# fails is fatal regardless, and the checksum is never optional.
#
# Anything that is not empty, 0, false or no counts as set. ('true' -eq '1' is
# False in PowerShell, so the obvious spelling of this test is a silent no-op.)
$AllowUnsigned = [bool]$env:CONSTLE_ALLOW_UNSIGNED -and
                 ($env:CONSTLE_ALLOW_UNSIGNED.ToLowerInvariant() -notin @('0', 'false', 'no'))

# CONSTLE_REQUIRE_SIGNATURE was the opt-IN to this behaviour, back when the
# default was lenient. It stays recognised so an existing CI file is not met
# with silence, but it can only be redundant now - and the one spelling that
# would weaken anything, setting it to 0, is reported and ignored rather than
# honoured. The report is deferred until Write-Warn exists, further down.
$LegacyRequire = if ($env:CONSTLE_REQUIRE_SIGNATURE) {
    $env:CONSTLE_REQUIRE_SIGNATURE.ToLowerInvariant()
} else {
    ''
}

# The identity the release signature must carry. Keyless signing has no fixed
# public key - anyone can get a valid certificate from Fulcio and sign
# anything - so a signature only means something once it is pinned to the
# workflow that was supposed to have produced it. These two values are the
# pin, and they are deliberately literals: building the expression from $Repo
# would need escaping to stay exact, and a mis-escaped pin is a pin that
# matches strangers. Keep them in step with README.md's "Verifying a release"
# section, and with scripts/install.
$CosignIdentityRegexp = '^https://github\.com/constle/constle/\.github/workflows/release\.yaml@refs/tags/v'
$CosignOidcIssuer     = 'https://token.actions.githubusercontent.com'

# Install here - no administrator rights needed because LOCALAPPDATA is the
# current user's own folder (e.g. C:\Users\yourname\AppData\Local\Programs\constle).
# CONSTLE_INSTALL_DIR overrides it; the check is explicit because Join-Path
# throws on a null path, which is what LOCALAPPDATA is on any non-Windows
# PowerShell.
if ($env:CONSTLE_INSTALL_DIR) {
    $InstallDir = $env:CONSTLE_INSTALL_DIR
} elseif ($env:LOCALAPPDATA) {
    $InstallDir = Join-Path (Join-Path $env:LOCALAPPDATA "Programs") "constle"
} else {
    Write-Host "`nerror: LOCALAPPDATA is not set, so there is no default install directory.`nSet CONSTLE_INSTALL_DIR to choose one.`n" -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# Pretty output helpers
# ---------------------------------------------------------------------------
function Write-Step { param($msg) Write-Host "  " -NoNewline; Write-Host "-> " -NoNewline -ForegroundColor Blue;  Write-Host $msg }
function Write-Ok   { param($msg) Write-Host "  " -NoNewline; Write-Host "[ok] " -NoNewline -ForegroundColor Green; Write-Host $msg }
# Yellow, and on the error stream. A weaker install is not a progress update;
# giving it the same blue arrow as "downloading..." is how it went unread for a
# release. Write-Warning is deliberately not used: it prefixes "WARNING: " and
# obeys $WarningPreference, which a caller's profile can set to silent.
function Write-Warn { param($msg) Write-Host "  " -NoNewline; Write-Host "! " -NoNewline -ForegroundColor Yellow; Write-Host $msg }
function Write-Fail { param($msg) $global:ProgressPreference = $PrevProgressPreference; Write-Host "`nerror: $msg`n" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "constle installer" -ForegroundColor White
Write-Host ""

# ---------------------------------------------------------------------------
# Where the bytes may come from
#
# An installer that will fetch over plain HTTP has no integrity left to offer:
# whoever can rewrite the archive on the wire rewrites checksums.txt in the same
# breath, and the comparison further down then passes on two files that agree
# with each other and with nothing else. Loopback is the one exception, because
# the regression test serves a fake release from 127.0.0.1, and because anyone
# who can point this at your own machine is already running code on it.
#
# This runs here, rather than beside the assignments, because Write-Fail has to
# exist before anything can call it.
# ---------------------------------------------------------------------------
foreach ($Pair in @(@('CONSTLE_INSTALL_BASE_URL', $BaseUrl), @('CONSTLE_INSTALL_API_URL', $ApiBaseUrl))) {
    if ($Pair[1] -notmatch '^https://' -and
        $Pair[1] -notmatch '^http://(127\.0\.0\.1|localhost|\[::1\])(:\d+)?(/|$)') {
        Write-Fail "$($Pair[0]) must be an https:// URL (or a loopback http:// address).`nRefusing to download over an unauthenticated transport. Nothing has been installed."
    }
}

# An overridden install must never read like a github.com install.
if ($BaseUrl -ne "https://github.com" -or $ApiBaseUrl -ne "https://api.github.com") {
    Write-Warn "release artifacts will be fetched from $BaseUrl, not github.com"
}

# The deferred report for CONSTLE_REQUIRE_SIGNATURE; see the note above.
if ($LegacyRequire -in @('0', 'false', 'no')) {
    Write-Warn "CONSTLE_REQUIRE_SIGNATURE=$env:CONSTLE_REQUIRE_SIGNATURE is ignored."
    Write-Warn "    A verified signature is required by default and this cannot switch it off."
    Write-Warn "    CONSTLE_ALLOW_UNSIGNED=1 is the only way to install without one."
} elseif ($LegacyRequire) {
    Write-Step "CONSTLE_REQUIRE_SIGNATURE is redundant; a verified signature is the default"
}

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

$ApiUrl = "$ApiBaseUrl/repos/$Repo/releases/latest"
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
# Tag "v0.5.0" -> archive "constle_0.5.0_windows_amd64.zip"
# but the GitHub URL path still uses the full tag: /download/v0.5.0/constle_0.5.0...
# ---------------------------------------------------------------------------
# The tag becomes part of a URL, part of a filename on this machine, and -
# once the archive is downloaded - the key looked up in checksums.txt. It is
# also not entirely ours: it is whatever the GitHub API replied with. Constrain
# it to the characters a version tag can actually contain, so that none of
# those three uses can be steered somewhere else by a tag containing a slash
# or a "..".
if ($Version -notmatch '^v[0-9][0-9A-Za-z.+_-]*$') {
    Write-Fail "refusing to install: '$Version' does not look like a release tag."
}

$VersionNoV = $Version.Substring(1)     # "v0.5.0" -> "0.5.0"
$Archive    = "constle_${VersionNoV}_windows_${Arch}.zip"
$ReleaseUrl = "$BaseUrl/$Repo/releases/download/$Version"
$Url        = "$ReleaseUrl/$Archive"

Write-Step "downloading $Archive..."

# ---------------------------------------------------------------------------
# Step 5: Download to a temporary directory
#
# [System.IO.Path]::GetTempPath()  -- e.g. C:\Users\yourname\AppData\Local\Temp\
# GetRandomFileName()               -- e.g. "constle-a3bx9q"
# ---------------------------------------------------------------------------
$TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) "constle-install-$(([System.IO.Path]::GetRandomFileName()).Replace('.',''))"
New-Item -ItemType Directory -Path $TmpDir | Out-Null

# The archive is saved under a fixed local name rather than under $Archive.
# $Archive is the key we will look up in checksums.txt, and keeping it out of
# any path this script writes to means the lookup key and the filesystem never
# have to agree about anything.
$ArchivePath   = Join-Path $TmpDir "archive.zip"
$ChecksumsPath = Join-Path $TmpDir "checksums.txt"
$SigPath       = Join-Path $TmpDir "checksums.txt.sig"
$CertPath      = Join-Path $TmpDir "checksums.txt.pem"

try {
    Invoke-WebRequest -Uri $Url -OutFile $ArchivePath -UseBasicParsing
} catch {
    Remove-Item -LiteralPath $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Fail "download failed: $_`nURL: $Url"
}

# ---------------------------------------------------------------------------
# Step 6: Verify the download
#
# Up to this point the archive is just bytes off the network. Two independent
# things have to hold before any of it is unpacked, or moved anywhere:
#
#   1. checksums.txt has to be the one this project published. Every release
#      carries a cosign signature over that file, so when cosign is on this
#      machine we check it, pinned to the identity of the release workflow.
#   2. The archive's SHA-256 has to equal the line checksums.txt has for it.
#
# They are checked in that order on purpose. A checksum is worth exactly as
# much as the file it was read from: someone who can replace the archive on a
# release can replace checksums.txt next to it just as easily, and would.
# Checking the signature first is what makes step 2 mean something.
#
# What happens when a link is missing rather than broken:
#
#   cosign not installed       -> stop, unless CONSTLE_ALLOW_UNSIGNED is set
#   release has no signature   -> stop, unless CONSTLE_ALLOW_UNSIGNED is set
#   signature present, FAILS   -> stop, always, with no way to override
#
# The first two are the only cases CONSTLE_ALLOW_UNSIGNED reaches, and it is
# the only thing that reaches them. The third is never negotiable, because an
# override there would turn every blocked network into a silent downgrade.
# ---------------------------------------------------------------------------
Write-Step "downloading checksums.txt..."
try {
    Invoke-WebRequest -Uri "$ReleaseUrl/checksums.txt" -OutFile $ChecksumsPath -UseBasicParsing
} catch {
    Remove-Item -LiteralPath $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Fail "release $Version has no checksums.txt, so $Archive cannot be verified.`nThis script will not install an unverified binary.`nSee: https://github.com/$Repo/releases/tag/$Version"
}

# ---- Link 1: is checksums.txt the file this project published? ------------
#
# cosign exits non-zero when it cannot prove that, and that exit status is the
# whole answer. We deliberately do not read what it printed: its output is
# derived from a file an attacker may have written, and a trust decision that
# greps attacker-influenced text is not a trust decision.
#
# $ErrorActionPreference = 'Stop' does NOT turn a non-zero exit code from a
# native program into a terminating error, so $LASTEXITCODE has to be checked
# by hand. It is cleared first so that a cosign that fails to launch at all
# cannot leave a stale 0 behind and read as success.
$SignatureState = $null

# -CommandType Application so a function or alias named cosign in the caller's
# profile cannot stand in for the real binary - under `iwr | iex` this script
# runs in the caller's session, where such definitions exist. (scripts/install
# closes the same hole with `command cosign`.) -First 1 because Get-Command can
# return more than one match.
$Cosign = Get-Command cosign -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1

#
# $SignatureHint travels with $SignatureState because the two reasons need
# different advice: installing cosign fixes the first and does nothing at all
# for the second. A refusal that offers the wrong remedy gets worked around.
$SignatureHint = $null

if (-not $Cosign) {
    $SignatureState = "cosign is not installed"
    $SignatureHint  = "Install cosign, then run this again:`n    https://docs.sigstore.dev/cosign/system_config/installation/"
} else {
    $HaveSignature = $true
    try {
        Invoke-WebRequest -Uri "$ReleaseUrl/checksums.txt.sig" -OutFile $SigPath  -UseBasicParsing
        Invoke-WebRequest -Uri "$ReleaseUrl/checksums.txt.pem" -OutFile $CertPath -UseBasicParsing
    } catch {
        $HaveSignature = $false
        $SignatureState = "release $Version was published without a signature"
        $SignatureHint  = "There is no signature on this release to check, so no local tool will help.`n    https://github.com/$Repo/releases/tag/$Version"
    }

    if ($HaveSignature) {
        Write-Step "verifying the signature over checksums.txt..."

        # Splat an argument ARRAY, never one interpolated string: the identity
        # regexp has to reach cosign with its backslashes and its leading ^
        # intact.
        $CosignArgs = @(
            'verify-blob',
            '--certificate',                 $CertPath,
            '--signature',                   $SigPath,
            '--certificate-identity-regexp', $CosignIdentityRegexp,
            '--certificate-oidc-issuer',     $CosignOidcIssuer,
            $ChecksumsPath
        )

        # Three things make this correct, and each is a bug if left out:
        #
        #   'Stop' does NOT turn a non-zero exit code from a native program into
        #   a PowerShell error, so $LASTEXITCODE has to be read by hand.
        #
        #   'Stop' PLUS 2>&1 on a native program is actively harmful: redirected
        #   stderr becomes error records and PowerShell raises a terminating
        #   NativeCommandError, so a cosign that prints an informational line and
        #   SUCCEEDS would kill the install. Hence 'Continue' across the call.
        #
        #   $LASTEXITCODE keeps its previous value if the program never launched
        #   at all, so it is cleared first and $null counts as failure.
        $PrevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $global:LASTEXITCODE = $null
        try {
            $CosignOut = & $Cosign.Source @CosignArgs 2>&1 | Out-String
        } finally {
            $ErrorActionPreference = $PrevEap
        }

        # Branch on the exit status only. cosign's output is derived from a file
        # an attacker may have written, and a trust decision that greps
        # attacker-influenced text is not a trust decision.
        if ($null -eq $LASTEXITCODE -or $LASTEXITCODE -ne 0) {
            Write-Host $CosignOut
            Remove-Item -LiteralPath $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
            Write-Fail "SIGNATURE VERIFICATION FAILED for checksums.txt of release $Version.`n`nThe signature does not prove this file came from $Repo's release workflow.`nNothing has been installed.`n`nIf you can reproduce this, please report it privately:`n  https://github.com/$Repo/security/advisories/new"
        }
        Write-Ok "signature verified: checksums.txt came from $Repo's release workflow"
    }
}

# A signature that could not be checked is a weaker install, not a safe one.
# Everything below this line is then a corruption check and nothing more, so by
# default this is where the install stops. It stops before the archive is
# unpacked, which is the only ordering that means anything.
if ($SignatureState) {
    if (-not $AllowUnsigned) {
        Remove-Item -LiteralPath $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Fail "cannot verify that release $Version came from $Repo`: $SignatureState.`n`nchecksums.txt is served from the same release as the archive, so on its own it`nshows the download was not corrupted - not that it came from this project.`nNothing has been installed.`n`n  $SignatureHint`n`n  Or, accepting an install this script cannot vouch for:`n    `$env:CONSTLE_ALLOW_UNSIGNED = '1'"
    }
    Write-Warn "CONSTLE_ALLOW_UNSIGNED is set, and $SignatureState."
    Write-Warn "    Continuing with the checksum alone. That shows this download is not"
    Write-Warn "    corrupted; it does NOT show it came from $Repo."
}

# ---- Link 2: is this archive the one checksums.txt names? ----------------
#
# GoReleaser writes one line per archive, as a lowercase SHA-256, two spaces,
# and the bare filename:
#
#   6a81d4f2...6465  constle_0.5.0_windows_amd64.zip
#
# The line is found by splitting each line and comparing the whole filename
# field for equality. -like would read the name as a wildcard pattern and
# -match would read it as a regular expression, where the dots in
# "constle_0.5.0_windows_amd64.zip" match any character at all. Requiring
# exactly one match means a missing entry and a duplicated entry both come
# back empty, and both are refused below.
$Expected = @(
    foreach ($line in Get-Content -LiteralPath $ChecksumsPath) {
        $fields = $line.Trim() -split '\s+', 2
        if ($fields.Count -eq 2 -and $fields[1].TrimStart('*') -ceq $Archive) { $fields[0] }
    }
)

# Exactly one entry, or refuse. Zero means there is nothing to check against,
# which must never quietly become "so skip the check". Two means somebody
# appended a line. The 64-hex test rejects an HTML error page or a truncated
# file that happened to split into two fields.
#
# \A and \z, not ^ and $: .NET's $ also matches just before a trailing
# newline, so '^[0-9a-f]{64}$' would accept a digest with an LF welded to it.
# Upper and lower case are both accepted, and the value is lowercased below,
# so that this file and scripts/install take exactly the same checksums.txt.
if ($Expected.Count -ne 1 -or $Expected[0] -notmatch '\A[0-9a-fA-F]{64}\z') {
    Remove-Item -LiteralPath $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Fail "checksums.txt for release $Version has no single entry for $Archive.`nThe archive cannot be verified, so it will not be installed."
}

# Get-FileHash returns the digest in UPPERCASE; checksums.txt is lowercase.
# Both sides are lowered before comparing rather than relying on PowerShell's
# -eq happening to ignore case.
Write-Step "verifying the checksum of $Archive..."
$ExpectedHash = $Expected[0].ToLowerInvariant()
$ActualHash   = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()

if ($ActualHash -cne $ExpectedHash) {
    Remove-Item -LiteralPath $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Fail "CHECKSUM MISMATCH for $Archive.`n`n  expected: $ExpectedHash`n  actual:   $ActualHash`n`nThe downloaded file is not the one this release published. That is either a`ncorrupted download or a tampered one. Nothing has been installed.`n`nIf it happens again, please report it privately:`n  https://github.com/$Repo/security/advisories/new"
}
Write-Ok "checksum verified: $Archive"

# ---------------------------------------------------------------------------
# Step 7: Extract the zip archive
#
# Expand-Archive is built into PowerShell 5.1+ and understands .zip files
# natively.  -Force overwrites existing files in the destination.
#
# It goes into its own subdirectory so that what comes out cannot land on top
# of checksums.txt or the archive itself, and the binary is then taken from
# the one path GoReleaser puts it at rather than searched for. Both of those
# only matter because the bytes are already verified - an archive that gets to
# choose which file becomes constle.exe has already won.
# ---------------------------------------------------------------------------
Write-Step "extracting..."
$UnpackDir = Join-Path $TmpDir "unpacked"
Expand-Archive -LiteralPath $ArchivePath -DestinationPath $UnpackDir -Force

$BinaryPath = Get-Item -LiteralPath (Join-Path $UnpackDir $BinaryName) -ErrorAction SilentlyContinue

if (-not $BinaryPath) {
    Remove-Item -LiteralPath $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Fail "binary '$BinaryName' not found in archive - please report at https://github.com/$Repo/issues"
}

# ---------------------------------------------------------------------------
# Step 8: Install
#
# Create the install directory if it doesn't exist (-Force does nothing if
# it already exists, unlike mkdir which would error).
# Then move the binary there.
# ---------------------------------------------------------------------------
Write-Step "installing to $InstallDir..."
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Move-Item -LiteralPath $BinaryPath.FullName -Destination (Join-Path $InstallDir $BinaryName) -Force

# ---------------------------------------------------------------------------
# Step 9: Add to the user PATH (if not already present)
#
# There are two levels of PATH on Windows:
#   Machine -- HKLM, applies to all users, requires admin to change
#   User    -- HKCU, applies only to the current user, no admin needed
#
# We modify the User-level PATH so constle is available in new shells without
# needing administrator rights.
#
# [System.Environment]::GetEnvironmentVariable(name, target) reads from the
# registry (persistent), not from the current process $env:PATH (ephemeral).
# We also update $env:PATH in the current process so constle works immediately
# in this same terminal session.
#
# The registry is a Windows idea. On any other platform .NET accepts the 'User'
# target and quietly does nothing with it, so the step is gated rather than
# left to report a success that did not happen. ($IsWindows only exists from
# PowerShell 6; on 5.1 there is nothing else this could be running on.)
# ---------------------------------------------------------------------------
$OnWindows = ($PSVersionTable.PSVersion.Major -lt 6) -or $IsWindows

if ($env:CONSTLE_INSTALL_DIR) {
    # Someone who named the directory is managing PATH themselves, and an
    # automated run must never accrete entries in a real user's - or a CI
    # runner's - persistent PATH, which is exactly what the regression test
    # would otherwise do on every single invocation.
    Write-Host "    add $InstallDir to your PATH."
} elseif (-not $OnWindows) {
    Write-Step "not on Windows: leaving PATH alone"
} else {
    # Compare whole PATH entries rather than searching for the directory as a
    # substring: a substring test calls ...\constle present when only
    # ...\constle-old is, and -like would read characters like [ and ] in the
    # path as a wildcard pattern.
    $UserPath  = [System.Environment]::GetEnvironmentVariable('PATH', 'User')
    $Separator = [System.IO.Path]::PathSeparator
    $Entries   = if ($UserPath) { $UserPath -split [regex]::Escape($Separator) } else { @() }
    $Present   = $Entries | Where-Object { $_.TrimEnd('\', '/') -ieq $InstallDir.TrimEnd('\', '/') }

    if (-not $Present) {
        $NewPath = if ($UserPath) { "$UserPath$Separator$InstallDir" } else { $InstallDir }

        # A PATH that could not be written is worth a warning, not a failed
        # install: the binary is already verified and in place by this point.
        try {
            [System.Environment]::SetEnvironmentVariable('PATH', $NewPath, 'User')
            $env:PATH = "$env:PATH$Separator$InstallDir"   # update current session too

            Write-Ok "added $InstallDir to user PATH"
            Write-Host "    (restart other terminals for PATH to take effect)"
        } catch {
            Write-Host "    could not update your PATH automatically: $_"
            Write-Host "    add this directory to it by hand: $InstallDir"
        }
    } else {
        Write-Ok "$InstallDir already in PATH"
    }
}

# ---------------------------------------------------------------------------
# Cleanup temporary files
# ---------------------------------------------------------------------------
Remove-Item -LiteralPath $TmpDir -Recurse -Force -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# Done!
# ---------------------------------------------------------------------------
Write-Host ""
# Say which guarantee was actually obtained. With CONSTLE_ALLOW_UNSIGNED this
# reduces to a corruption check, and the last line before the binary is on PATH
# is the wrong place to be vague about that.
if ($SignatureState) {
    Write-Ok "constle $Version installed to $InstallDir (checksum verified; signature NOT checked - CONSTLE_ALLOW_UNSIGNED)"
} else {
    Write-Ok "constle $Version installed to $InstallDir (checksum and signature verified)"
}
Write-Host ""
Write-Host "  Get started:"
Write-Host "    constle --help"
Write-Host "    constle validate agent.yaml"
Write-Host ""

# Restore what we changed in the caller's session (see the note at the top).
$ProgressPreference = $PrevProgressPreference
