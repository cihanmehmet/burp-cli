#!/bin/bash

# Build script for burp-cli - All platforms
# Usage: ./build-all.sh

set -e

VERSION=$(grep 'const VERSION' burp-cli.go | awk -F'"' '{print $2}')
BUILD_DIR="builds"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Building burp-cli v${VERSION} for all platforms"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Create builds directory
mkdir -p ${BUILD_DIR}

# Build function
build() {
    local GOOS=$1
    local GOARCH=$2
    local OUTPUT=$3
    
    echo "Building ${OUTPUT}..."
    GOOS=${GOOS} GOARCH=${GOARCH} go build -ldflags "-s -w" -o ${BUILD_DIR}/${OUTPUT}
    
    if [ $? -eq 0 ]; then
        echo "✓ ${OUTPUT} ($(du -h ${BUILD_DIR}/${OUTPUT} | cut -f1))"
    else
        echo "✗ Failed to build ${OUTPUT}"
        return 1
    fi
}

echo "🍎 macOS Builds:"
build darwin arm64 burp-cli_v${VERSION}_darwin_arm64
build darwin amd64 burp-cli_v${VERSION}_darwin_amd64
echo ""

echo "🐧 Linux Builds:"
build linux arm64 burp-cli_v${VERSION}_linux_arm64
build linux amd64 burp-cli_v${VERSION}_linux_amd64
echo ""

echo "🪟 Windows Builds:"
build windows amd64 burp-cli_v${VERSION}_windows_amd64.exe
build windows arm64 burp-cli_v${VERSION}_windows_arm64.exe
build windows 386 burp-cli_v${VERSION}_windows_x86.exe
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Build Complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📦 Binaries created in ./${BUILD_DIR}/"
ls -lh ${BUILD_DIR}/
echo ""
echo "📋 File sizes:"
du -h ${BUILD_DIR}/* | sort -h
echo ""
echo "🚀 To create release archives:"
echo "   cd ${BUILD_DIR}"
echo "   tar -czf burp-cli_v${VERSION}_darwin_arm64.tar.gz burp-cli_v${VERSION}_darwin_arm64"
echo "   tar -czf burp-cli_v${VERSION}_linux_amd64.tar.gz burp-cli_v${VERSION}_linux_amd64"
echo "   zip burp-cli_v${VERSION}_windows_amd64.zip burp-cli_v${VERSION}_windows_amd64.exe"
