#!/bin/sh

circle crash.cc
if [ "$?" = 139 ]; then
  exit 0
else
  exit 1
fi
