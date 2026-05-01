#!/usr/bin/env bash
set -euo pipefail

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default options
BUILD_TYPE="Release"
CLEAN=false
DRY_RUN=false
VERBOSE=false
JOBS=""
INSTALL=false
INSTALL_PREFIX=""

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    
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
}

# Show usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Build Atlus on Linux or macOS"
    echo ""
    echo "Options:"
    echo "  -c, --clean           Clean build (remove build directory first)"
    echo "  -t, --type TYPE       Build type: Release, Debug, RelWithDebInfo (default: Release)"
    echo "  -j, --jobs N          Number of parallel jobs (default: auto)"
    echo "  -i, --install PREFIX  Install to PREFIX after build"
    echo "  -v, --verbose         Enable verbose output"
    echo "  -n, --dry-run         Show what would be done without executing"
    echo "  -h, --help            Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                    # Release build"
    echo "  $0 -c -t Debug        # Clean debug build"
    echo "  $0 -j 8               # Build with 8 parallel jobs"
    echo "  $0 -i /usr/local      # Build and install to /usr/local"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--clean)
            CLEAN=true
            shift
            ;;
        -t|--type)
            BUILD_TYPE="$2"
            shift 2
            ;;
        -j|--jobs)
            JOBS="$2"
            shift 2
            ;;
        -i|--install)
            INSTALL=true
            INSTALL_PREFIX="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -n|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            log ERROR "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Validate build type
case "$BUILD_TYPE" in
    Release|Debug|RelWithDebInfo|MinSizeRel)
        ;;
    *)
        log ERROR "Invalid build type: $BUILD_TYPE"
        log ERROR "Valid types: Release, Debug, RelWithDebInfo, MinSizeRel"
        exit 1
        ;;
esac

# Determine platform
PLATFORM="$(uname -s)"
ARCH="$(uname -m)"
log INFO "Building Atlus on $PLATFORM ($ARCH)"
log INFO "Build type: $BUILD_TYPE"

# Get script and project directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$ROOT_DIR/build"

# Auto-detect parallel jobs
if [[ -z "$JOBS" ]]; then
    if command -v nproc >/dev/null 2>&1; then
        JOBS=$(nproc)
    elif command -v sysctl >/dev/null 2>&1; then
        JOBS=$(sysctl -n hw.ncpu)
    else
        JOBS=4
    fi
fi
log INFO "Using $JOBS parallel jobs"

# Dry run check
run_cmd() {
    if [[ "$DRY_RUN" = true ]]; then
        log INFO "[DRY-RUN] $*"
        return 0
    fi
    "$@"
}

# Clean build directory if requested
if [[ "$CLEAN" = true ]]; then
    if [[ -d "$BUILD_DIR" ]]; then
        log INFO "Cleaning build directory..."
        run_cmd rm -rf "$BUILD_DIR"
    fi
fi

# Create build directory
log INFO "Creating build directory..."
run_cmd mkdir -p "$BUILD_DIR"

# Determine generator and options
CMAKE_ARGS=(
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE"
    -S "$ROOT_DIR"
    -B "$BUILD_DIR"
)

# Platform-specific options
if [[ "$PLATFORM" == "Darwin" ]]; then
    # macOS-specific settings
    CMAKE_ARGS+=(-DCMAKE_OSX_DEPLOYMENT_TARGET=11.0)
    
    # Detect architecture for universal binary
    if [[ "$ARCH" == "arm64" ]]; then
        log INFO "Building for Apple Silicon (arm64)"
        CMAKE_ARGS+=(-DCMAKE_OSX_ARCHITECTURES=arm64)
    elif [[ "$ARCH" == "x86_64" ]]; then
        log INFO "Building for Intel (x86_64)"
        CMAKE_ARGS+=(-DCMAKE_OSX_ARCHITECTURES=x86_64)
    fi
    
    # Check for Homebrew and set prefix if needed
    if command -v brew >/dev/null 2>&1; then
        BREW_PREFIX=$(brew --prefix)
        log INFO "Using Homebrew from $BREW_PREFIX"
        CMAKE_ARGS+=(-DCMAKE_PREFIX_PATH="$BREW_PREFIX")
    fi
fi

# Install prefix
if [[ "$INSTALL" = true ]]; then
    CMAKE_ARGS+=(-DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX")
fi

# Verbose makefiles
if [[ "$VERBOSE" = true ]]; then
    CMAKE_ARGS+=(-DCMAKE_VERBOSE_MAKEFILE=ON)
fi

# Configure
echo ""
log INFO "Configuring with CMake..."
if [[ "$VERBOSE" = true ]]; then
    log INFO "CMake arguments: ${CMAKE_ARGS[*]}"
fi

if ! run_cmd cmake "${CMAKE_ARGS[@]}"; then
    log ERROR "CMake configuration failed"
    exit 1
fi

# Build
echo ""
log INFO "Building..."
BUILD_ARGS=(--build "$BUILD_DIR" --parallel "$JOBS")
if [[ "$VERBOSE" = true ]]; then
    BUILD_ARGS+=(--verbose)
fi

if ! run_cmd cmake "${BUILD_ARGS[@]}"; then
    log ERROR "Build failed"
    exit 1
fi

log SUCCESS "Build completed successfully!"

# Install if requested
if [[ "$INSTALL" = true ]]; then
    echo ""
    log INFO "Installing to $INSTALL_PREFIX..."
    if ! run_cmd cmake --install "$BUILD_DIR"; then
        log ERROR "Installation failed"
        exit 1
    fi
    log SUCCESS "Installation complete!"
fi

echo ""
log INFO "Build artifacts: $BUILD_DIR"
if [[ -f "$BUILD_DIR/Atlus" ]]; then
    log INFO "  Executable: $BUILD_DIR/Atlus"
fi

exit 0
