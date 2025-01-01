#!/bin/bash

run "$@"
#run -DVANILLA_NACL -I/usr/include/sodium "$@"
run -DHAVE_LIBEV "$@"
