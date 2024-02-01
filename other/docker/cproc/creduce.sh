#!/bin/sh

cproc -c broken.c 2>&1 | grep "tq == QUALNONE"
