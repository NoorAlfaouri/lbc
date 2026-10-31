#!/bin/sh
# LBC (Lossless Block Codec) Installer
# Install on any Linux / macOS / BSD system:
#   curl -fsSL https://raw.githubusercontent.com/NoorAlfaouri/lbc/master/install.sh | bash

set -eu

echo "================================================================="
echo "  Installing LBC (Lossless Block Codec)"
echo "================================================================="

# Detect C compiler
if command -v cc >/dev/null 2>&1; then
    CC="cc"
elif command -v gcc >/dev/null 2>&1; then
    CC="gcc"
elif command -v clang >/dev/null 2>&1; then
    CC="clang"
else
    echo "Error: No C compiler found (cc, gcc, or clang is required)." >&2
    exit 1
fi

TMP_DIR=$(mktemp -d)
trap 'rm -rf -- "$TMP_DIR"' EXIT

REPO_URL="${LBC_REPO_URL:-https://github.com/NoorAlfaouri/lbc.git}"
echo "Downloading source from $REPO_URL..."

if [ -f "lbc.c" ] && [ -f "lbc.h" ]; then
    echo "Installing from local source directory..."
    SRC_DIR="$PWD"
else
    git clone --depth 1 "$REPO_URL" "$TMP_DIR/lbc"
    SRC_DIR="$TMP_DIR/lbc"
fi

echo "Compiling with $CC -O3..."
"$CC" -pipe -std=c11 -O3 -Wall -Wextra -pedantic -D_POSIX_C_SOURCE=200809L "$SRC_DIR/lbc.c" -o "$TMP_DIR/lbc"

# Determine target directory
if [ "$(id -u)" -eq 0 ]; then
    BIN_DIR="/usr/local/bin"
    INC_DIR="/usr/local/include"
else
    BIN_DIR="$HOME/.local/bin"
    INC_DIR="$HOME/.local/include"
fi

mkdir -p "$BIN_DIR" "$INC_DIR"
cp -f "$TMP_DIR/lbc" "$BIN_DIR/lbc"
chmod 755 "$BIN_DIR/lbc"
cp -f "$SRC_DIR/lbc.h" "$INC_DIR/lbc.h"
chmod 644 "$INC_DIR/lbc.h"

echo "================================================================="
echo "  LBC successfully installed to $BIN_DIR/lbc!"
echo "  Run 'lbc --help' to get started."
echo "================================================================="
