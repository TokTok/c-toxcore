#!/usr/bin/env bash

set -eux -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

ARCH="$1"
"$SCRIPT_DIR/deps.sh" ios "$ARCH"

export PKG_CONFIG_PATH="$PWD/prefix/lib/pkgconfig"

IOS_FLAGS="-miphoneos-version-min=10.0 -arch $ARCH"

if [ "$ARCH" = "i386" ] || [ "$ARCH" = "x86_64" ]; then
  XC_SDK="iphonesimulator"
else
  XC_SDK="iphoneos"
fi

# Build for iOS 10
cmake \
  -B _build \
  -G Ninja \
  -DCMAKE_INSTALL_PREFIX="$PWD/toxcore-ios-$ARCH" \
  -DCMAKE_BUILD_TYPE=Release \
  -DENABLE_STATIC=ON \
  -DENABLE_SHARED=ON \
  -DMUST_BUILD_TOXAV=ON \
  -DDHT_BOOTSTRAP=OFF \
  -DBOOTSTRAP_DAEMON=OFF \
  -DUNITTEST=OFF \
  -DMIN_LOGGER_LEVEL=TRACE \
  -DEXPERIMENTAL_API=ON \
  -DCMAKE_C_FLAGS="$IOS_FLAGS" \
  -DCMAKE_CXX_FLAGS="$IOS_FLAGS" \
  -DCMAKE_EXE_LINKER_FLAGS="$IOS_FLAGS" \
  -DCMAKE_SHARED_LINKER_FLAGS="$IOS_FLAGS" \
  -DCMAKE_OSX_SYSROOT="$(xcrun --sdk "$XC_SDK" --show-sdk-path)" \
  -DCMAKE_OSX_ARCHITECTURES="$ARCH"

"$SCRIPT_DIR/build.sh" "toxcore-ios-$ARCH"
