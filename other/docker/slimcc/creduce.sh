#!/bin/sh

chibicc -c broken.c 2>&1 | grep "error"
