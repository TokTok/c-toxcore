#!/bin/sh

echo "#include <assert.h>" >crash-gcc.c
cat crash.c >>crash-gcc.c
if ! gcc -std=c99 -I/usr/include/x86_64-linux-musl -O2 -Wall -Wno-unused -Werror -c -o /dev/null crash-gcc.c; then
  rm crash-gcc.c
  exit 1
fi
rm crash-gcc.c
/work/cake/src/cake -fanalyzer crash.c
if [ $? != 139 ]; then
  exit 1
fi
