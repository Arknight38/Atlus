#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Default options
$BuildType = "Release"
$Clean = $false
$DryRun = $false
$Verbose = $false
$Jobs = 0
$Install = $false
$InstallPrefix = ""
$Architecture = "x64"
$Generator = ""

# Parse arguments
for ($i = 0; $i -lt $args.Count; $i++) {
    switch ($args[$i]) {
        "-c" { $Clean = $true }
        "--clean" { $Clean = $true }
        "-t" {
            if ($i + 1 -lt $args.Count) {
                $BuildType = $args[$i + 1]
                $i++
            }
        }
        "--type" {
            if ($i + 1 -lt $args.Count) {
                $BuildType = $args[$i + 1]
                $i++
            }
        }
        "-j" {
            if ($i + 1 -lt $args.Count) {
                $Jobs = [int]$args[$i + 1]
                $i++
            }
        }
        "--jobs" {
            if ($i + 1 -lt $args.Count) {
                $Jobs = [int]$args[$i + 1]
                $i++
            }
        }
        "-i" {
            $Install = $true
            if ($i + 1 -lt $args.Count) {
                $InstallPrefix = $args[$i + 1]
                $i++
            }
        }
        "--install" {
            $Install = $true
            if ($i + 1 -lt $args.Count) {
                $InstallPrefix = $args[$i + 1]
                $i++
            }
        }
        "-a" {
            if ($i + 1 -lt $args.Count) {
                $Architecture = $args[$i + 1]
                $i++
            }
        }
        "--arch" {
            if ($i + 1 -lt $args.Count) {
                $Architecture = $args[$i + 1]
                $i++
            }
        }
        "-G" {
            if ($i + 1 -lt $args.Count) {
                $Generator = $args[$i + 1]
                $i++
            }
        }
        "--generator" {
            if ($i + 1 -lt $args.Count) {
                $Generator = $args[$i + 1]
                $i++
            }
        }
        "-v" { $Verbose = $true }
        "--verbose" { $Verbose = $true }
        "-n" { $DryRun = $true }
        "--dry-run" { $DryRun = $true }
        "-h" { Show-Usage; exit 0 }
        "--help" { Show-Usage; exit 0 }
        default {
            Write-Error "Unknown option: $($args[$i])"
            Write-Host "Use --help for usage information"
            exit 1
        }
    }
}

function Show-Usage {
    Write-Host "Usage: $($MyInvocation.MyCommand.Name) [OPTIONS]"
    Write-Host ""
    Write-Host "Build Atlus on Windows"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -c, --clean           Clean build (remove build directory first)"
    Write-Host "  -t, --type TYPE       Build type: Release, Debug, RelWithDebInfo (default: Release)"
    Write-Host "  -j, --jobs N          Number of parallel jobs (default: auto)"
    Write-Host "  -a, --arch ARCH       Architecture: x64, Win32 (default: x64)"
    Write-Host "  -G, --generator GEN   CMake generator (default: auto-detect)"
    Write-Host "  -i, --install PREFIX  Install to PREFIX after build"
    Write-Host "  -v, --verbose         Enable verbose output"
    Write-Host "  -n, --dry-run         Show what would be done without executing"
    Write-Host "  -h, --help            Show this help message"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\build.ps1                    # Release build"
    Write-Host "  .\build.ps1 -c -t Debug        # Clean debug build"
    Write-Host "  .\build.ps1 -j 8               # Build with 8 parallel jobs"
    Write-Host "  .\build.ps1 -G 'Ninja Multi-Config'  # Specific generator"
}

# Logging
function Log {
    param([string]$Level, [string]$Message)
    $color = switch ($Level) {
        "INFO"    { "Cyan" }
        "SUCCESS" { "Green" }
        "WARNING" { "Yellow" }
        "ERROR"   { "Red" }
        default   { "White" }
    }
    Write-Host "[$Level] $Message" -ForegroundColor $color
}

# FIX 1 -- Defender exclusions
function Add-DefenderExclusion {
    param([string]$Path)
    try {
        $existing = (Get-MpPreference).ExclusionPath
        if ($existing -notcontains $Path) {
            Add-MpPreference -ExclusionPath $Path -ErrorAction Stop
            Log INFO "Added Defender exclusion: $Path"
        } else {
            Log INFO "Defender exclusion already present: $Path"
        }
    } catch {
        Log WARNING "Could not add Defender exclusion (run as admin to enable this): $_"
    }
}

# FIX 2 -- Streaming process runner with timeout
function Invoke-CommandSafe {
    param(
        [string]$Command,
        [string[]]$Arguments = @(),
        [int]$TimeoutSeconds = 0
    )

    if ($DryRun) {
        Log INFO "[DRY-RUN] $Command $($Arguments -join ' ')"
        return $true
    }

    if ($Verbose) {
        Log INFO "Running: $Command $($Arguments -join ' ')"
    }

    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName               = $Command
        # Quote arguments containing spaces to preserve them
        $quotedArgs = $Arguments | ForEach-Object {
            if ($_ -match '\s') { '"' + $_ + '"' } else { $_ }
        }
        $psi.Arguments              = $quotedArgs -join ' '
        $psi.UseShellExecute        = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.CreateNoWindow         = $true

        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $psi

        # Event-based output handling
        $stdoutLines = [System.Collections.ArrayList]::new()
        $stderrLines = [System.Collections.ArrayList]::new()

        $stdoutHandler = {
            $line = $Event.SourceEventArgs.Data
            if ($null -ne $line) {
                $Event.MessageData.Add($line) | Out-Null
                Write-Host $line
            }
        }

        $stderrHandler = {
            $line = $Event.SourceEventArgs.Data
            if ($null -ne $line) {
                $Event.MessageData.Add($line) | Out-Null
                Write-Host $line -ForegroundColor DarkYellow
            }
        }

        $null = Register-ObjectEvent -InputObject $proc -EventName "OutputDataReceived" -Action $stdoutHandler -MessageData $stdoutLines
        $null = Register-ObjectEvent -InputObject $proc -EventName "ErrorDataReceived" -Action $stderrHandler -MessageData $stderrLines

        $proc.Start() | Out-Null
        $proc.BeginOutputReadLine()
        $proc.BeginErrorReadLine()

        $deadline = if ($TimeoutSeconds -gt 0) {
            [DateTime]::Now.AddSeconds($TimeoutSeconds)
        } else { [DateTime]::MaxValue }

        while (-not $proc.HasExited) {
            if ([DateTime]::Now -gt $deadline) {
                Log WARNING "Process timed out after ${TimeoutSeconds}s -- killing"
                $proc.Kill()
                return $false
            }
            Start-Sleep -Milliseconds 100
        }

        $proc.WaitForExit()
        Start-Sleep -Milliseconds 500

        if ($proc.ExitCode -ne 0) {
            Log ERROR "Command failed with exit code $($proc.ExitCode)"
            return $false
        }
        return $true

    } catch {
        Log ERROR "Command failed: $_"
        return $false
    }
}

# Validate build type
$validBuildTypes = @("Release", "Debug", "RelWithDebInfo", "MinSizeRel")
if ($validBuildTypes -notcontains $BuildType) {
    Log ERROR "Invalid build type: $BuildType"
    Log ERROR "Valid types: $($validBuildTypes -join ', ')"
    exit 1
}

# Validate architecture
$validArchitectures = @("x64", "Win32", "ARM64")
if ($validArchitectures -notcontains $Architecture) {
    Log ERROR "Invalid architecture: $Architecture"
    Log ERROR "Valid architectures: $($validArchitectures -join ', ')"
    exit 1
}

# Directories
$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir    = Split-Path -Parent $ScriptDir
$BuildDir   = Join-Path $RootDir "build"
$VcpkgDir   = Join-Path $RootDir "third_party\vcpkg"

Log INFO "Building Atlus on Windows"
Log INFO "Build type: $BuildType"
Log INFO "Architecture: $Architecture"

# Auto-detect parallel jobs
if ($Jobs -eq 0) {
    $Jobs = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
    if ($Jobs -eq 0) { $Jobs = 4 }
}
Log INFO "Using $Jobs parallel jobs"

# FIX 1 -- Add Defender exclusions before any build activity
Add-DefenderExclusion $BuildDir
Add-DefenderExclusion $RootDir

# Check for required tools
if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
    Log ERROR "CMake is required but not found in PATH"
    Log ERROR "Please install CMake from https://cmake.org/download/"
    exit 1
}

$cmakeVersionOutput = cmake --version
$cmakeVersion = [regex]::Match($cmakeVersionOutput, "cmake version (\d+\.\d+)").Groups[1].Value
if ($cmakeVersion) {
    Log INFO "CMake version: $cmakeVersion"
}

# Check for vcpkg
$vcpkgTool = $null
if (Test-Path (Join-Path $VcpkgDir "vcpkg.exe")) {
    $vcpkgTool = Join-Path $VcpkgDir "vcpkg.exe"
    Log INFO "Using vcpkg from: $vcpkgTool"
} else {
    Log WARNING "vcpkg not found at $VcpkgDir"
    Log WARNING "Run setup.ps1 first to bootstrap dependencies"
}

# Clean build directory if requested
if ($Clean) {
    if (Test-Path $BuildDir) {
        Log INFO "Cleaning build directory..."
        if (-not $DryRun) {
            Remove-Item -Recurse -Force $BuildDir
        }
    }
}

# Create build directory
Log INFO "Creating build directory..."
if (-not $DryRun) {
    New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
}

# CMake args
$CMakeArgs = @()

# FIX 3 -- Prefer Visual Studio for MSVC/Qt6 compatibility, fall back to Ninja
if (-not $Generator) {
    $vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vsWhere) {
        $vsVersion = & $vsWhere -latest -property catalog_productLineVersion
        if ($vsVersion) {
            $Generator = "Visual Studio 18 2026"
            Log INFO "Using Visual Studio $vsVersion generator (MSVC for Qt6 compatibility)"
        }
    }
    if (-not $Generator -and (Get-Command ninja -ErrorAction SilentlyContinue)) {
        $Generator = "Ninja Multi-Config"
        Log INFO "Using Ninja generator (Visual Studio not found)"
    }
}

if ($Generator) {
    $CMakeArgs += "-G", $Generator
}

# Architecture (not used with Ninja -- it inherits from the environment)
if ($Generator -notlike "*Ninja*") {
    $CMakeArgs += "-A", $Architecture
}

# Track if using MSVC for HEAP flags
$UsingMSVC = $Generator -match "Visual Studio|Ninja"

$CMakeArgs += "-DCMAKE_BUILD_TYPE=$BuildType"

# vcpkg toolchain
if ($vcpkgTool) {
    $toolchainFile = Join-Path $VcpkgDir "scripts\buildsystems\vcpkg.cmake"
    if (Test-Path $toolchainFile) {
        $CMakeArgs += "-DCMAKE_TOOLCHAIN_FILE=$toolchainFile"
        Log INFO "Using vcpkg toolchain: $toolchainFile"
    }
}

# Qt6 path
$Qt6Dir = "C:\Qt\6.8.0\msvc2022_64"
if (Test-Path (Join-Path $Qt6Dir "lib\cmake\Qt6\Qt6Config.cmake")) {
    $CMakeArgs += "-DCMAKE_PREFIX_PATH=$Qt6Dir"
    Log INFO "Using Qt6 from: $Qt6Dir"
} else {
    Log WARNING "Qt6 not found at $Qt6Dir - run setup.ps1 to install"
}

# FIX 4 -- Linker heap size to prevent memory stall during large link jobs (MSVC only)
if ($UsingMSVC) {
    $CMakeArgs += "-DCMAKE_EXE_LINKER_FLAGS=/HEAP:1000000000"
    $CMakeArgs += "-DCMAKE_SHARED_LINKER_FLAGS=/HEAP:1000000000"
}

# Install prefix
if ($Install -and $InstallPrefix) {
    $CMakeArgs += "-DCMAKE_INSTALL_PREFIX=$InstallPrefix"
}

if ($Verbose) {
    $CMakeArgs += "-DCMAKE_VERBOSE_MAKEFILE=ON"
}

$CMakeArgs += "-S", $RootDir
$CMakeArgs += "-B", $BuildDir

# Configure
Write-Host ""
Log INFO "Configuring with CMake..."
if ($Verbose) {
    Log INFO "CMake arguments: $($CMakeArgs -join ' ')"
}

if (-not (Invoke-CommandSafe "cmake" $CMakeArgs)) {
    Log ERROR "CMake configuration failed"
    exit 1
}

# Build -- 30 minute timeout; if it exceeds this something is genuinely wrong
Write-Host ""
Log INFO "Building..."
$BuildArgs = @("--build", $BuildDir, "--config", $BuildType, "--parallel", $Jobs)
if ($Verbose) {
    $BuildArgs += "--verbose"
}

if (-not (Invoke-CommandSafe "cmake" $BuildArgs -TimeoutSeconds 1800)) {
    Log ERROR "Build failed or timed out after 30 minutes"
    Log ERROR "Check Task Manager: if link.exe is at 0% CPU and 0% I/O, re-run as admin so Defender exclusions can be applied"
    exit 1
}

Log SUCCESS "Build completed successfully!"

# Deploy Qt6 and vcpkg DLLs
$exePath = Join-Path $BuildDir "$BuildType\Atlus.exe"
if (Test-Path $exePath) {
    Log INFO "Deploying Qt6 dependencies..."
    $winDeployQt = Join-Path $Qt6Dir "bin\windeployqt.exe"
    if (Test-Path $winDeployQt) {
        if (-not (Invoke-CommandSafe $winDeployQt @("--release", "--no-translations", "--no-compiler-runtime", $exePath))) {
            Log WARNING "windeployqt may have encountered issues, continuing..."
        }
    } else {
        Log WARNING "windeployqt.exe not found at $winDeployQt"
    }

    # Copy vcpkg DLLs
    $vcpkgBinDir = "C:\vcpkg\installed\x64-windows\bin"
    if (Test-Path $vcpkgBinDir) {
        Log INFO "Copying vcpkg DLLs..."
        $releaseDir = Join-Path $BuildDir $BuildType
        Get-ChildItem -Path $vcpkgBinDir -Filter "*.dll" | ForEach-Object {
            $destPath = Join-Path $releaseDir $_.Name
            if (-not (Test-Path $destPath)) {
                Copy-Item $_.FullName $destPath -ErrorAction SilentlyContinue
            }
        }
    }
} else {
    Log WARNING "Executable not found at expected path: $exePath"
}

# Install if requested
if ($Install) {
    Write-Host ""
    if ($InstallPrefix) {
        Log INFO "Installing to $InstallPrefix..."
    } else {
        Log INFO "Installing..."
    }

    $InstallArgs = @("--install", $BuildDir, "--config", $BuildType)
    if (-not (Invoke-CommandSafe "cmake" $InstallArgs)) {
        Log ERROR "Installation failed"
        exit 1
    }
    Log SUCCESS "Installation complete!"
}

# Summary
Write-Host ""
Log INFO "Build summary:"
Log INFO "  Build directory: $BuildDir"
Log INFO "  Build type:      $BuildType"
Log INFO "  Architecture:    $Architecture"

$exePath = Join-Path $BuildDir "bin\$BuildType\Atlus.exe"
if (-not (Test-Path $exePath)) {
    $exePath = Join-Path $BuildDir "$BuildType\Atlus.exe"
}
if (Test-Path $exePath) {
    Log INFO "  Executable: $exePath"
    Log SUCCESS "Build ready to run!"
} else {
    Log WARNING "Executable not found at expected path -- searching..."
    $found = Get-ChildItem -Path $BuildDir -Recurse -Filter "Atlus.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) {
        Log INFO "  Found executable: $($found.FullName)"
    }
}

if (-not $DryRun -and -not $Install) {
    Write-Host ""
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

exit 0