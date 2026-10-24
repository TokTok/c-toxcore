#!/bin/bash

set -eux -o pipefail

# Cross-compiles with the image other/docker/windows/windows.Dockerfile
# builds: a DLL with its dependencies linked in.
ARCH=x86_64

rm -rf _windows "toxcore-windows-$ARCH"
mkdir _windows
docker run --rm \
  -v "$PWD:/toxcore:ro" \
  -v "$PWD/_windows:/prefix" \
  -e ENABLE_ARCH_i686=false \
  -e ENABLE_ARCH_x86_64=true \
  -e EXTRA_CMAKE_FLAGS="-DMUST_BUILD_TOXAV=ON -DMIN_LOGGER_LEVEL=TRACE" \
  toxchat/windows:win64
cp -r "_windows/$ARCH" "toxcore-windows-$ARCH"
