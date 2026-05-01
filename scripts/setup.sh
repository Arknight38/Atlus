#!/usr/bin/env bash
set -euo pipefail

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default options
DRY_RUN=false
VERBOSE=false
LOG_FILE=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --log)
            LOG_FILE="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Setup third-party dependencies for Atlus"
            echo ""
            echo "Options:"
            echo "  --dry-run     Show what would be done without executing"
            echo "  --verbose     Enable verbose output"
            echo "  --log FILE    Write log to FILE"
            echo "  --help, -h    Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        INFO)
            echo -e "${BLUE}[INFO]${NC} $message"
            ;;
        SUCCESS)
            echo -e "${GREEN}[SUCCESS]${NC} $message"
            ;;
        WARNING)
            echo -e "${YELLOW}[WARNING]${NC} $message"
            ;;
        ERROR)
            echo -e "${RED}[ERROR]${NC} $message"
            ;;
        *)
            echo "[$level] $message"
            ;;
    esac
    
    if [[ -n "$LOG_FILE" ]]; then
        echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    fi
}

# Run command (or echo in dry-run mode)
run_cmd() {
    if [[ "$DRY_RUN" = true ]]; then
        log INFO "[DRY-RUN] $*"
        return 0
    fi
    
    if [[ "$VERBOSE" = true ]]; then
        log INFO "Running: $*"
    fi
    
    if ! "$@"; then
        log ERROR "Command failed: $*"
        return 1
    fi
}

# Verify command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Download with retry
download_with_retry() {
    local url="$1"
    local output="$2"
    local max_retries=3
    local retry_count=0
    
    while [[ $retry_count -lt $max_retries ]]; do
        if run_cmd curl -fL --retry 3 --retry-delay 2 "$url" -o "$output"; then
            return 0
        fi
        retry_count=$((retry_count + 1))
        log WARNING "Download failed (attempt $retry_count/$max_retries): $url"
        sleep 2
    done
    
    log ERROR "Failed to download after $max_retries attempts: $url"
    return 1
}

# Verify checksum
verify_checksum() {
    local file="$1"
    local expected="$2"
    
    if [[ ! -f "$file" ]]; then
        log ERROR "File not found for checksum verification: $file"
        return 1
    fi
    
    local actual
    if command_exists sha256sum; then
        actual=$(sha256sum "$file" | awk '{print $1}')
    elif command_exists shasum; then
        actual=$(shasum -a 256 "$file" | awk '{print $1}')
    else
        log WARNING "Checksum verification skipped (no sha256sum/shasum available)"
        return 0
    fi
    
    if [[ "$actual" != "$expected" ]]; then
        log ERROR "Checksum mismatch for $file"
        log ERROR "Expected: $expected"
        log ERROR "Actual:   $actual"
        return 1
    fi
    
    log SUCCESS "Checksum verified for $file"
    return 0
}

# Validate installation
validate_tool() {
    local tool_path="$1"
    local tool_name="$2"
    
    if [[ ! -f "$tool_path" ]]; then
        log ERROR "$tool_name not found at $tool_path"
        return 1
    fi
    
    if [[ ! -x "$tool_path" ]]; then
        log ERROR "$tool_name is not executable: $tool_path"
        return 1
    fi
    
    log SUCCESS "$tool_name validated at $tool_path"
    return 0
}

PLATFORM="$(uname -s)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
THIRD_PARTY="$ROOT_DIR/third_party"

log INFO "Setting up Atlus third-party dependencies on $PLATFORM"

# Check required commands
if ! command_exists git; then
    log ERROR "git is required but not installed"
    exit 1
fi

if ! command_exists curl; then
    log ERROR "curl is required but not installed"
    exit 1
fi

# --- Git Submodules ---
log INFO "Initializing submodules..."
if ! run_cmd git -C "$ROOT_DIR" submodule update --init --recursive; then
    log ERROR "Failed to initialize submodules"
    exit 1
fi

# --- rev.ng ---
log INFO "Installing rev.ng..."
REVNG_DIR="$THIRD_PARTY/revng"
run_cmd mkdir -p "$REVNG_DIR"

if [ "$PLATFORM" = "Linux" ]; then
    if [ ! -f "$REVNG_DIR/revng" ]; then
        local revng_url="https://rev.ng/downloads/revng-distributable/latest/revng-distributable-x86_64-linux.tar.gz"
        local revng_tar="/tmp/revng.tar.gz"
        
        log INFO "Downloading rev.ng from $revng_url"
        if ! download_with_retry "$revng_url" "$revng_tar"; then
            log ERROR "Failed to download rev.ng"
            exit 1
        fi
        
        # Note: Add expected checksum here once available
        # verify_checksum "$revng_tar" "expected_sha256_hash"
        
        log INFO "Extracting rev.ng..."
        if ! run_cmd tar -xzf "$revng_tar" -C "$REVNG_DIR" --strip-components=1; then
            log ERROR "Failed to extract rev.ng"
            run_cmd rm -f "$revng_tar"
            exit 1
        fi
        
        run_cmd rm -f "$revng_tar"
        
        if validate_tool "$REVNG_DIR/revng" "rev.ng"; then
            log SUCCESS "rev.ng installed to $REVNG_DIR"
        else
            log WARNING "rev.ng installation completed but validation failed"
        fi
    else
        log INFO "rev.ng already present, skipping."
    fi
elif [ "$PLATFORM" = "Darwin" ]; then
    log WARNING "rev.ng does not officially support macOS."
    log WARNING "You can run it via Docker: docker pull revng/revng"
    log WARNING "Skipping native install."
fi

# --- vcpkg (for LIEF) ---
log INFO "Bootstrapping vcpkg..."
VCPKG_DIR="$THIRD_PARTY/vcpkg"
if [ ! -d "$VCPKG_DIR" ]; then
    log INFO "Cloning vcpkg..."
    if ! run_cmd git clone --depth 1 https://github.com/microsoft/vcpkg "$VCPKG_DIR"; then
        log ERROR "Failed to clone vcpkg"
        exit 1
    fi
fi

if ! run_cmd "$VCPKG_DIR/bootstrap-vcpkg.sh" -disableMetrics; then
    log ERROR "Failed to bootstrap vcpkg"
    exit 1
fi

log INFO "Installing vcpkg packages..."
local triplet="$([ "$PLATFORM" = "Darwin" ] && echo x64-osx || echo x64-linux)"
if ! run_cmd "$VCPKG_DIR/vcpkg" install lief --triplet "$triplet"; then
    log ERROR "Failed to install lief via vcpkg"
    exit 1
fi

# --- Zydis (submodule, but verify) ---
ZYDIS_DIR="$THIRD_PARTY/zydis"
if [ ! -f "$ZYDIS_DIR/CMakeLists.txt" ]; then
    log WARNING "Zydis submodule missing. Re-running submodule update..."
    if ! run_cmd git -C "$ROOT_DIR" submodule update --init --recursive; then
        log ERROR "Failed to update submodules for Zydis"
        exit 1
    fi
fi

# --- Qt6 ---
log INFO "Checking Qt6 development packages..."

# Check for Qt6 CMake config
qt6_found=false
if pkg-config --exists Qt6Core 2>/dev/null || \
   [ -d "/usr/lib/x86_64-linux-gnu/cmake/Qt6" ] || \
   [ -d "/usr/lib/cmake/Qt6" ] || \
   [ -d "/usr/local/lib/cmake/Qt6" ]; then
    qt6_found=true
fi

if [ "$qt6_found" = false ]; then
    log INFO "Qt6 dev packages not detected. Attempting install via package manager..."
    if command_exists apt-get; then
        # Debian / Ubuntu
        if ! run_cmd sudo apt-get update; then
            log WARNING "apt-get update failed, continuing..."
        fi
        if ! run_cmd sudo apt-get install -y qt6-base-dev qt6-tools-dev libqt6widgets6; then
            log ERROR "Failed to install Qt6 via apt"
            exit 1
        fi
    elif command_exists dnf; then
        # Fedora / RHEL
        if ! run_cmd sudo dnf install -y qt6-qtbase-devel qt6-qttools-devel; then
            log ERROR "Failed to install Qt6 via dnf"
            exit 1
        fi
    elif command_exists pacman; then
        # Arch
        if ! run_cmd sudo pacman -S --needed --noconfirm qt6-base qt6-tools; then
            log ERROR "Failed to install Qt6 via pacman"
            exit 1
        fi
    else
        log WARNING "No supported package manager found. Please install Qt6 development packages manually."
    fi
else
    log INFO "Qt6 development packages appear to be installed."
fi

echo ""
log SUCCESS "Done! Third-party setup complete."
log INFO "    rev.ng:  $REVNG_DIR"
log INFO "    vcpkg:   $VCPKG_DIR"
log INFO "    zydis:   $ZYDIS_DIR"

# Pause if running interactively to prevent terminal from closing
if [[ "$DRY_RUN" = false && -t 1 ]]; then
    echo ""
    read -p "Press Enter to exit..."
fi
