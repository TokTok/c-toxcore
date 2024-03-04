FROM alpine:3.19.0 AS cake

RUN apk add --no-cache \
  clang \
  compiler-rt \
  gdb \
  git \
  libsodium-dev \
  libvpx-dev \
  linux-headers \
  llvm \
  musl-dev \
  opus-dev \
  util-linux-dev

WORKDIR /src/workspace/cake
ARG CAKE_COMMIT="64a51a9e92e1ed620c2416f8209c186f5c01af61"
RUN ["git", "clone", "https://github.com/thradams/cake", "/src/workspace/cake"]
RUN git checkout "$CAKE_COMMIT"

WORKDIR /src/workspace/cake/src
RUN sed -i \
 -e 's/ -Wall / -std=gnu2x -Wall -Wno-multichar -Wno-int-conversion -Wno-unused-but-set-variable -Wno-incompatible-pointer-types-discards-qualifiers -Werror -static -ggdb3 /' \
 -e 's/RUN "amalgamator.exe/"echo amalgamator.exe/' \
 build.c \
 && clang -DDEBUG build.c -o build \
 && ./build

ENV CAKEFLAGS="-D__x86_64__ -I/src/workspace/cake/src/include -I/src/workspace/cake/src -I/usr/include/"
#ENV CAKEFLAGS="-D__x86_64__ -I/src/workspace/cake/src/include -I/src/workspace/cake/src -I/usr/include/ -fanalyzer -Wno-analyzer-maybe-uninitialized"

WORKDIR /src/workspace/c-toxcore
COPY . /src/workspace/c-toxcore/

RUN for i in toxcore/*.c; do \
    OUT="$(/src/workspace/cake/src/cake $CAKEFLAGS "$i")"; \
    echo "$OUT"; \
    if echo "$OUT" | grep "warning:" >/dev/null; then exit 1; fi; \
    if echo "$OUT" | grep " 0 files" >/dev/null; then exit 1; fi; \
  done

# For creduce:
#FROM ubuntu:22.04
#
#RUN apt-get update && \
# DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends \
# creduce \
# libopus-dev \
# libsodium-dev \
# libvpx-dev \
# linux-libc-dev \
# musl-dev \
# && apt-get clean \
# && rm -rf /var/lib/apt/lists/*
#
#COPY --from=cake /src/workspace/cake/src/cake /src/workspace/cake/src/cake
#
#WORKDIR /src/workspace/c-toxcore
#COPY . /src/workspace/c-toxcore/
#
#RUN /src/workspace/cake/src/cake -D__x86_64__ -I/usr/include/x86_64-linux-musl -I/usr/include/ -E toxcore/DHT.c | grep -Ev '^(Cake|/| [01])' >crash.c
#RUN other/docker/cake/creduce.sh
#RUN creduce other/docker/cake/creduce.sh crash.c
#
#RUN apt-get update && \
# DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends \
# gdb \
# && apt-get clean \
# && rm -rf /var/lib/apt/lists/*
#COPY --from=cake /src/workspace/cake/src /src/workspace/c-toxcore/
#RUN gdb -ex r -ex bt --args /src/workspace/cake/src/cake -fanalyzer crash.c
