#!/bin/bash -eu

# out of tree build
cd "$WORK"

ls /usr/local/lib/

# Debug build for asserts
cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER="$CC" \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
  -DCMAKE_EXE_LINKER_FLAGS="$LIB_FUZZING_ENGINE" \
  -DBUILD_TOXAV=OFF -DENABLE_SHARED=NO -DBUILD_FUZZ_TESTS=ON \
  -DDHT_BOOTSTRAP=OFF -DBOOTSTRAP_DAEMON=OFF "$SRC"/c-toxcore

# build fuzzer target
cmake --build ./ --target bootstrap_fuzzer

# copy to output files
cp "$WORK"/bootstrap_fuzzer "$OUT"/
