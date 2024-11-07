#!/usr/bin/env bash

WARNINGS=(-std=c99 -Wall -Wno-return-type -Wno-unused -Werror)

if ! gcc "${WARNINGS[@]}" -I/src/workspace/c-toxcore/toxcore -I/usr/include/x86_64-linux-musl -fsyntax-only crash.c; then
  exit 1
fi
/src/workspace/cake/src/cake -I/src/workspace/c-toxcore/toxcore -I/src/workspace/cake/src/include -I/src/workspace/cake/src -fanalyzer crash.c
if [ $? != 139 ]; then
  exit 1
fi
