#!/usr/bin/env bash

set -eux -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

ARCH="$1"
"$SCRIPT_DIR/deps.sh" macos "$ARCH"

export PKG_CONFIG_PATH="$PWD/prefix/lib/pkgconfig"

# Build for macOS
cmake \
  -B _build \
  -G Ninja \
  -DCMAKE_INSTALL_PREFIX="$PWD/toxcore-macos-$ARCH" \
  -DCMAKE_BUILD_TYPE=Release \
  -DENABLE_STATIC=ON \
  -DENABLE_SHARED=ON \
  -DMUST_BUILD_TOXAV=ON \
  -DDHT_BOOTSTRAP=OFF \
  -DBOOTSTRAP_DAEMON=OFF \
  -DUNITTEST=OFF \
  -DMIN_LOGGER_LEVEL=TRACE \
  -DEXPERIMENTAL_API=ON \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=10.15

"$SCRIPT_DIR/build.sh" "toxcore-macos-$ARCH"
