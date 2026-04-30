#!/usr/bin/env bash
set -euo pipefail

PLATFORM="$(uname -s)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
THIRD_PARTY="$ROOT_DIR/third_party"

echo "==> Setting up Atlus third-party dependencies on $PLATFORM"

# --- Git Submodules ---
echo "==> Initializing submodules..."
git -C "$ROOT_DIR" submodule update --init --recursive

# --- rev.ng ---
echo "==> Installing rev.ng..."
REVNG_DIR="$THIRD_PARTY/revng"
mkdir -p "$REVNG_DIR"

if [ "$PLATFORM" = "Linux" ]; then
    if [ ! -f "$REVNG_DIR/revng" ]; then
        # Download the revng distribution via their official installer
        curl -L https://rev.ng/downloads/revng-distributable/latest/revng-distributable-x86_64-linux.tar.gz \
            -o /tmp/revng.tar.gz
        tar -xzf /tmp/revng.tar.gz -C "$REVNG_DIR" --strip-components=1
        rm /tmp/revng.tar.gz
        echo "    rev.ng installed to $REVNG_DIR"
    else
        echo "    rev.ng already present, skipping."
    fi
elif [ "$PLATFORM" = "Darwin" ]; then
    echo "    WARNING: rev.ng does not officially support macOS."
    echo "    You can run it via Docker: docker pull revng/revng"
    echo "    Skipping native install."
fi

# --- vcpkg (for LIEF) ---
echo "==> Bootstrapping vcpkg..."
VCPKG_DIR="$THIRD_PARTY/vcpkg"
if [ ! -d "$VCPKG_DIR" ]; then
    git clone --depth 1 https://github.com/microsoft/vcpkg "$VCPKG_DIR"
fi
"$VCPKG_DIR/bootstrap-vcpkg.sh" -disableMetrics

echo "==> Installing vcpkg packages..."
"$VCPKG_DIR/vcpkg" install lief --triplet "$([ "$PLATFORM" = "Darwin" ] && echo x64-osx || echo x64-linux)"

# --- Zydis (submodule, but verify) ---
ZYDIS_DIR="$THIRD_PARTY/zydis"
if [ ! -f "$ZYDIS_DIR/CMakeLists.txt" ]; then
    echo "    WARNING: Zydis submodule missing. Re-running submodule update..."
    git -C "$ROOT_DIR" submodule update --init --recursive
fi

# --- ImGui (verify docking branch) ---
IMGUI_DIR="$THIRD_PARTY/imgui"
if [ ! -f "$IMGUI_DIR/imgui.h" ]; then
    echo "    ImGui missing, cloning docking branch..."
    rm -rf "$IMGUI_DIR"
    git clone --depth 1 --branch docking \
        https://github.com/ocornut/imgui "$IMGUI_DIR"
fi

echo ""
echo "==> Done! Third-party setup complete."
echo "    rev.ng:  $REVNG_DIR"
echo "    vcpkg:   $VCPKG_DIR"
echo "    imgui:   $IMGUI_DIR"
echo "    zydis:   $ZYDIS_DIR"
