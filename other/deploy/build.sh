#!/usr/bin/env bash

set -eux -o pipefail

INSTALL_PATH="$1"

cmake --build _build
cmake --install _build

# Need to use GNU ar because the default ar on macOS doesn't support the -M flag.
export PATH="/opt/homebrew/opt/binutils/bin:/usr/local/opt/binutils/bin:$PATH"

# Merge toxcore, opus, vpx, and sodium into a single static library.
ar -M <<EOF
create libtoxcore.a
addlib $INSTALL_PATH/lib/libtoxcore.a
addlib prefix/lib/libopus.a
addlib prefix/lib/libsodium.a
addlib prefix/lib/libvpx.a
save
end
EOF

# Replace the original toxcore library with the merged one.
mv libtoxcore.a "$INSTALL_PATH/lib/libtoxcore.a"

# Remove pkg-config directory. It's useless because these libraries aren't
# meant to be used in a normal pkg-config project.
rm -rf "$INSTALL_PATH/lib/pkgconfig"
