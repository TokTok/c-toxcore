#!/usr/bin/env bash

set -eux -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

"$SCRIPT_DIR/deps.sh" macos

export PKG_CONFIG_PATH="$PWD/prefix/lib/pkgconfig"

# Build
cmake \
  -B _build \
  -G Ninja \
  -DCMAKE_INSTALL_PREFIX="$PWD/toxcore-macos-$(uname -m)" \
  -DCMAKE_BUILD_TYPE=Release \
  -DENABLE_STATIC=OFF \
  -DENABLE_SHARED=ON \
  -DMUST_BUILD_TOXAV=ON \
  -DDHT_BOOTSTRAP=OFF \
  -DBOOTSTRAP_DAEMON=OFF \
  -DUNITTEST=OFF \
  -DMIN_LOGGER_LEVEL=TRACE

cmake --build _build
cmake --install _build
