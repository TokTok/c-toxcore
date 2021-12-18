#!/bin/bash

CPPFLAGS="-DMIN_LOGGER_LEVEL=LOGGER_LEVEL_TRACE"
CPPFLAGS+=("-isystem" "/usr/include/opus")
CPPFLAGS+=("-Iauto_tests")
CPPFLAGS+=("-Iother")
CPPFLAGS+=("-Iother/bootstrap_daemon/src")
CPPFLAGS+=("-Iother/fun")
CPPFLAGS+=("-Itesting")
CPPFLAGS+=("-Itesting/fuzzing")
CPPFLAGS+=("-Itesting/groupchats")
CPPFLAGS+=("-Itoxcore")
CPPFLAGS+=("-Itoxav")
CPPFLAGS+=("-Itoxencryptsave")

LDFLAGS=("-lopus" "-lsodium" "-lvpx" "-lpthread" "-lconfig" "-lgtest")
LDFLAGS+=("-fuse-ld=gold")
LDFLAGS+=("-Wl,--detect-odr-violations")
LDFLAGS+=("-Wl,--warn-common")
LDFLAGS+=("-Wl,--warn-execstack")
LDFLAGS+=("-Wl,-z,noexecstack")
LDFLAGS+=("-Wl,-z,now")

put() {
  if [ "$SKIP_LINES" = "" ]; then
    echo "#line 1 \"$1\"" >>amalgamation.cc
  fi
  cat "$1" >>amalgamation.cc
}

putmain() {
  echo "namespace ${1//[^a-zA-Z0-9_]/_} {" >>amalgamation.cc
  if [ "$SKIP_LINES" = "" ]; then
    echo "#line 1 \"$1\"" >>amalgamation.cc
  fi
  sed -e 's/^int main(/static &/' "$1" >>amalgamation.cc
  echo "} //  namespace ${1//[^a-zA-Z0-9_]/_}" >>amalgamation.cc
}

callmain() {
  echo "  call(${1//[^a-zA-Z0-9_]/_}::main, argc, argv);" >>amalgamation.cc
}

: >amalgamation.cc

put auto_tests/check_compat.h

# Include all C and C++ code
FIND_QUERY="find . '-(' -name '*.c' -or -name '*.cc' '-)'"
# Excludes
FIND_QUERY="$FIND_QUERY -and -not -wholename './_build/*'"
FIND_QUERY="$FIND_QUERY -and -not -wholename './super_donators/*'"
FIND_QUERY="$FIND_QUERY -and -not -name amalgamation.cc"
FIND_QUERY="$FIND_QUERY -and -not -name av_test.c"
FIND_QUERY="$FIND_QUERY -and -not -name dht_test.c"
FIND_QUERY="$FIND_QUERY -and -not -name trace.cc"
FIND_QUERY="$FIND_QUERY -and -not -name version_test.c"
FIND_QUERY="$FIND_QUERY -and -not -name bootstrap_harness.cc"
FIND_QUERY="$FIND_QUERY -and -not -name toxsave_harness.cc"
FIND_QUERY="$FIND_QUERY -and -not -name network_adapter.c"

readarray -t FILES <<<"$(eval "$FIND_QUERY")"

(for i in "${FILES[@]}"; do
  grep -o '#include <[^>]*>' "$i" |
    grep -E -v '<win|<ws|<iphlp|<libc|<mach/|<crypto_|<randombytes|<u.h>|<sys/filio|<stropts.h>|<linux'
done) | sort -u >>amalgamation.cc

echo 'namespace {' >>amalgamation.cc
for i in "${FILES[@]}"; do
  if ! grep -q '^int main(' "$i"; then
    put "$i"
  fi
done

for i in "${FILES[@]}"; do
  if grep -q '^int main(' "$i"; then
    putmain "$i"
  fi
done

echo "static void call(int m(), int argc, char **argv) { m(); }" >>amalgamation.cc
echo "static void call(int m(int, char **), int argc, char **argv) { m(argc, argv); }" >>amalgamation.cc
echo '}  // namespace' >>amalgamation.cc

echo "int main(int argc, char **argv) {" >>amalgamation.cc
for i in "${FILES[@]}"; do
  if grep -q '^int main(' "$i"; then
    callmain "$i"
  fi
done
echo "  return 0;" >>amalgamation.cc
echo "}" >>amalgamation.cc
