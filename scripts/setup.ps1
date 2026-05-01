#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Default options
$DryRun = $false
$Verbose = $false
$LogFile = ""

# Parse arguments
for ($i = 0; $i -lt $args.Count; $i++) {
    switch ($args[$i]) {
        "--dry-run" {
            $DryRun = $true
        }
        "--verbose" {
            $Verbose = $true
        }
        "--log" {
            if ($i + 1 -lt $args.Count) {
                $LogFile = $args[$i + 1]
                $i++
            } else {
                Write-Error "--log requires a file path"
                exit 1
            }
        }
        "--help" {
            Write-Host "Usage: $($MyInvocation.MyCommand.Name) [OPTIONS]"
            Write-Host ""
            Write-Host "Setup third-party dependencies for Atlus on Windows"
            Write-Host ""
            Write-Host "Options:"
            Write-Host "  --dry-run     Show what would be done without executing"
            Write-Host "  --verbose     Enable verbose output"
            Write-Host "  --log FILE    Write log to FILE"
            Write-Host "  --help        Show this help message"
            exit 0
        }
        default {
            Write-Error "Unknown option: $($args[$i])"
            Write-Host "Use --help for usage information"
            exit 1
        }
    }
}

# Logging function
function Log {
    param(
        [string]$Level,
        [string]$Message
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "INFO" { "Cyan" }
        "SUCCESS" { "Green" }
        "WARNING" { "Yellow" }
        "ERROR" { "Red" }
        default { "White" }
    }
    
    Write-Host "[$Level] $Message" -ForegroundColor $color
    
    if ($LogFile) {
        "[$timestamp] [$Level] $Message" | Out-File -FilePath $LogFile -Append
    }
}

# Run command (or echo in dry-run mode)
function Invoke-CommandSafe {
    param(
        [string]$Command,
        [string[]]$Arguments
    )
    
    if ($DryRun) {
        Log INFO "[DRY-RUN] $Command $Arguments"
        return $true
    }
    
    if ($Verbose) {
        Log INFO "Running: $Command $Arguments"
    }
    
    try {
        $output = & $Command @Arguments 2>&1
        if ($LASTEXITCODE -ne 0) {
            Log ERROR "Command failed with exit code ${LASTEXITCODE}: $Command $Arguments"
            if ($output) {
                Log ERROR "Output: $output"
            }
            return $false
        }
        return $true
    } catch {
        Log ERROR "Command failed: $_"
        return $false
    }
}

# Download with retry
function Download-WithRetry {
    param(
        [string]$Url,
        [string]$Output,
        [int]$MaxRetries = 3
    )
    
    $retryCount = 0
    while ($retryCount -lt $MaxRetries) {
        try {
            if ($DryRun) {
                Log INFO "[DRY-RUN] Downloading $Url to $Output"
                return $true
            }
            
            if ($Verbose) {
                Log INFO "Downloading $Url (attempt $($retryCount + 1)/$MaxRetries)"
            }
            
            Invoke-WebRequest -Uri $Url -OutFile $Output -UseBasicParsing -TimeoutSec 300
            return $true
        } catch {
            $retryCount++
            Log WARNING "Download failed (attempt $retryCount/$MaxRetries): $Url"
            if ($retryCount -lt $MaxRetries) {
                Start-Sleep -Seconds 2
            }
        }
    }
    
    Log ERROR "Failed to download after $MaxRetries attempts: $Url"
    return $false
}

# Verify checksum
function Test-FileChecksum {
    param(
        [string]$FilePath,
        [string]$ExpectedHash
    )
    
    if (-not (Test-Path $FilePath)) {
        Log ERROR "File not found for checksum verification: $FilePath"
        return $false
    }
    
    try {
        $actualHash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.ToLower()
        $expectedHash = $ExpectedHash.ToLower()
        
        if ($actualHash -ne $expectedHash) {
            Log ERROR "Checksum mismatch for $FilePath"
            Log ERROR "Expected: $expectedHash"
            Log ERROR "Actual:   $actualHash"
            return $false
        }
        
        Log SUCCESS "Checksum verified for $FilePath"
        return $true
    } catch {
        Log ERROR "Failed to verify checksum: $_"
        return $false
    }
}

# Validate installation
function Test-ToolInstallation {
    param(
        [string]$ToolPath,
        [string]$ToolName
    )
    
    if (-not (Test-Path $ToolPath)) {
        Log ERROR "$ToolName not found at $ToolPath"
        return $false
    }
    
    Log SUCCESS "$ToolName validated at $ToolPath"
    return $true
}

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir    = Split-Path -Parent $ScriptDir
$ThirdParty = Join-Path $RootDir "third_party"

Log INFO "Setting up Atlus third-party dependencies on Windows"

# Check required commands
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Log ERROR "git is required but not installed"
    exit 1
}

# --- Git Submodules ---
Log INFO "Initializing submodules..."
if (-not (Invoke-CommandSafe git @("-C", $RootDir, "submodule", "update", "--init", "--recursive"))) {
    Log ERROR "Failed to initialize submodules"
    exit 1
}

# --- rev.ng (Windows: Docker or WSL only) ---
Log INFO "Checking rev.ng availability..."
$RevngDir = Join-Path $ThirdParty "revng"
New-Item -ItemType Directory -Force -Path $RevngDir | Out-Null

$dockerAvailable = Get-Command docker -ErrorAction SilentlyContinue
$wslAvailable = Get-Command wsl -ErrorAction SilentlyContinue

if ($dockerAvailable) {
    Log INFO "Docker found. Pulling rev.ng image..."
    if (Invoke-CommandSafe docker pull revng/revng) {
        Log INFO "rev.ng available via: docker run --rm -v .:/wd revng/revng"
        
        # Write a helper batch file so the rest of Atlus can invoke it uniformly
        $batchContent = @"
@echo off
docker run --rm -v "%CD%:/wd" revng/revng %*
"@
        if (-not $DryRun) {
            $batchContent | Set-Content (Join-Path $RevngDir "revng.cmd")
        }
        Log SUCCESS "rev.ng helper script created"
    } else {
        Log ERROR "Failed to pull rev.ng Docker image"
        exit 1
    }
} elseif ($wslAvailable) {
    # Check if rev.ng is already installed in WSL
    $envCheck = wsl bash -c "test -f ~/revng/environment && echo OK || echo MISSING"
    if ($envCheck -eq "OK") {
        Log INFO "rev.ng already installed in WSL at ~/revng"
    } else {
        Log INFO "WSL found. Installing rev.ng inside WSL..."
        $wslScriptContent = @'
#!/bin/bash
set -e
cd ~
curl -L -s https://rev.ng/downloads/revng-distributable/master/install.sh | bash
echo 'rev.ng installed'
'@

        $wslScriptPath = Join-Path $env:TEMP "install_revng.sh"
        if (-not $DryRun) {
            $wslScriptContent | Set-Content -Path $wslScriptPath -Encoding ASCII
        }

        # Get the WSL path for the temp file (e.g., /mnt/c/...)
        $wslTempPath = wsl wslpath -u $wslScriptPath.Replace('\', '/')

        if (-not (Invoke-CommandSafe wsl @("bash", $wslTempPath))) {
            Log ERROR "Failed to install rev.ng in WSL"
            exit 1
        }

        # Cleanup temp script
        if (-not $DryRun -and (Test-Path $wslScriptPath)) {
            Remove-Item $wslScriptPath -ErrorAction SilentlyContinue
        }
    }

    # Verify the environment file actually exists
    $envCheck = wsl bash -c "test -f ~/revng/environment && echo OK || echo MISSING"
    if ($envCheck -ne "OK") {
        Log ERROR "rev.ng environment file not found at ~/revng/environment"
        Log ERROR "The installer may have failed or used a different path."
        exit 1
    }

    # Helper shim so Windows callers can invoke via WSL
    $batchContent = @"
@echo off
wsl bash -c "source ~/revng/environment && revng %*"
"@
    if (-not $DryRun) {
        $batchContent | Set-Content (Join-Path $RevngDir "revng.cmd")
    }
    Log SUCCESS "rev.ng available via WSL"
} else {
    Log WARNING "Neither Docker nor WSL detected."
    Log WARNING "rev.ng requires one of these on Windows."
    Log WARNING "Install Docker Desktop or enable WSL2, then re-run this script."
}

# --- vcpkg (for LIEF) ---
Log INFO "Bootstrapping vcpkg..."
$VcpkgDir = Join-Path $ThirdParty "vcpkg"
if (-not (Test-Path $VcpkgDir)) {
    Log INFO "Cloning vcpkg..."
    if (-not (Invoke-CommandSafe git @("clone", "--depth", "1", "https://github.com/microsoft/vcpkg", $VcpkgDir))) {
        Log ERROR "Failed to clone vcpkg"
        exit 1
    }
}

if (-not (Invoke-CommandSafe "$VcpkgDir\bootstrap-vcpkg.bat" @("-disableMetrics"))) {
    Log ERROR "Failed to bootstrap vcpkg"
    exit 1
}

Log INFO "Installing vcpkg packages..."
if (-not (Invoke-CommandSafe "$VcpkgDir\vcpkg.exe" @("install", "lief", "--triplet", "x64-windows"))) {
    Log ERROR "Failed to install lief via vcpkg"
    exit 1
}

# --- Zydis ---
$ZydisDir = Join-Path $ThirdParty "zydis"
if (-not (Test-Path (Join-Path $ZydisDir "CMakeLists.txt"))) {
    Log WARNING "Zydis submodule missing, re-running submodule update..."
    if (-not (Invoke-CommandSafe git @("-C", $RootDir, "submodule", "update", "--init", "--recursive"))) {
        Log ERROR "Failed to update submodules for Zydis"
        exit 1
    }
}

# --- Qt6 ---
Log INFO "Checking Qt6 installation..."
$Qt6Dir = "C:\Qt\6.8.0\msvc2022_64"
$Qt6CMake = Join-Path $Qt6Dir "lib\cmake\Qt6\Qt6Config.cmake"

if (-not (Test-Path $Qt6CMake)) {
    Log INFO "Qt6 not found at $Qt6Dir. Checking aqtinstall..."
    $aqt = Get-Command aqt -ErrorAction SilentlyContinue
    if (-not $aqt) {
        $pip = Get-Command pip -ErrorAction SilentlyContinue
        if (-not $pip) {
            Log ERROR "pip not found. Install Python + pip, then run: pip install aqtinstall"
            exit 1
        }
        Log INFO "Installing aqtinstall via pip..."
        if (-not (Invoke-CommandSafe pip @("install", "aqtinstall"))) {
            Log ERROR "Failed to install aqtinstall"
            exit 1
        }
    }
    Log INFO "Installing Qt6 6.8.0 via aqtinstall..."
    if (-not (Invoke-CommandSafe aqt @("install-qt", "windows", "desktop", "6.8.0", "win64_msvc2022_64", "--outputdir", "C:\Qt"))) {
        Log ERROR "Failed to install Qt6 via aqtinstall"
        exit 1
    }
} else {
    Log INFO "Qt6 found at $Qt6Dir"
}

Write-Host ""
Log SUCCESS "Done! Third-party setup complete."
Log INFO "    rev.ng:  $RevngDir"
Log INFO "    vcpkg:   $VcpkgDir"
Log INFO "    zydis:   $ZydisDir"
Log INFO "    qt6:     $Qt6Dir"

# Pause if running interactively to prevent window from closing
if (-not $DryRun) {
    Write-Host ""
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
