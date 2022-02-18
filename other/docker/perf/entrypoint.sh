#!/bin/sh

set -eux

TEST=conference_test
OUTPUT="/work/c-toxcore/test.perf"

gcc -pthread -g \
  -o "/work/$TEST" -O3 -fno-omit-frame-pointer \
  $(find /work/c-toxcore/tox* -name "*.c") \
  /work/c-toxcore/auto_tests/auto_test_support.c \
  /work/c-toxcore/testing/misc_tools.c \
  "/work/c-toxcore/auto_tests/$TEST.c" \
  -DMIN_LOGGER_LEVEL=LOGGER_LEVEL_TRACE \
  $(pkg-config --cflags --libs libsodium msgpack opus vpx)

time perf record -g --call-graph dwarf --freq=999 "/work/$TEST" /work/c-toxcore/auto_tests/
perf report | head -n50
perf script -F +pid > "$OUTPUT"
chown 1000:100 "$OUTPUT"
