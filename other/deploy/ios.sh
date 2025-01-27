#!/usr/bin/env bash

set -eux -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

"$SCRIPT_DIR/deps.sh" ios

export PKG_CONFIG_PATH="$PWD/prefix/lib/pkgconfig"

IOS_FLAGS="-miphoneos-version-min=10.0 -arch arm64"

# Build for iOS 10
cmake \
  -B _build \
  -G Ninja \
  -DCMAKE_INSTALL_PREFIX="$PWD/toxcore-ios-$(uname -m)" \
  -DCMAKE_BUILD_TYPE=Release \
  -DENABLE_STATIC=OFF \
  -DENABLE_SHARED=ON \
  -DMUST_BUILD_TOXAV=ON \
  -DDHT_BOOTSTRAP=OFF \
  -DBOOTSTRAP_DAEMON=OFF \
  -DUNITTEST=OFF \
  -DMIN_LOGGER_LEVEL=TRACE \
  -DCMAKE_C_FLAGS="$IOS_FLAGS" \
  -DCMAKE_CXX_FLAGS="$IOS_FLAGS" \
  -DCMAKE_EXE_LINKER_FLAGS="$IOS_FLAGS" \
  -DCMAKE_SHARED_LINKER_FLAGS="$IOS_FLAGS" \
  -DCMAKE_OSX_SYSROOT="$(xcrun --sdk iphoneos --show-sdk-path)"

cmake --build _build
cmake --install _build
