FROM alpine:3.19.0 AS cake

RUN ["apk", "add", "--no-cache", \
 "clang", \
 "compiler-rt", \
 "gdb", \
 "git", \
 "libsodium-dev", \
 "libvpx-dev", \
 "linux-headers", \
 "llvm", \
 "musl-dev", \
 "opus-dev", \
 "util-linux-dev"]

WORKDIR /src/workspace/cake
ARG CAKE_COMMIT="74c514edd8fefb1ecfe943259ec0efc9253c274d"
RUN ["git", "clone", "https://github.com/thradams/cake", "/src/workspace/cake"]
RUN git checkout "$CAKE_COMMIT"

WORKDIR /src/workspace/cake/src
RUN sed -i \
 -e 's/ -Wall / -DNDEBUG -std=gnu2x -Wall -Wno-pointer-sign -Wno-multichar -Wno-int-conversion -Wno-unused-but-set-variable -Wno-incompatible-pointer-types-discards-qualifiers -Wno-unused-function -Wno-unused-variable -Wno-unused-label -Wno-return-type -Werror -static -ggdb3 /' \
 -e 's/RUN "amalgamator.exe/"echo amalgamator.exe/' \
 build.c \
 && clang -DDEBUG build.c -o build \
 && ./build

# ENV CAKEFLAGS="-D__x86_64__ -I/src/workspace/cake/src/include -I/src/workspace/cake/src -I/usr/include"
ENV CAKEFLAGS="-D__x86_64__ -I/src/workspace/cake/src/include -I/src/workspace/cake/src -I/usr/include -fanalyzer"

WORKDIR /src/workspace/c-toxcore
COPY . /src/workspace/c-toxcore/

RUN for i in toxcore/*.c; do \
    echo "$i"; \
    OUT="$(/src/workspace/cake/src/cake $CAKEFLAGS "$i")"; \
    echo "$OUT"; \
    if echo "$OUT" | grep "error:" >/dev/null; then exit 1; fi; \
    if echo "$OUT" | grep "warning:" >/dev/null; then exit 1; fi; \
    if echo "$OUT" | grep " 0 files" >/dev/null; then exit 1; fi; \
  done

# For creduce:
#FROM ubuntu:22.04
#
#ENV DEBIAN_FRONTEND="noninteractive"
#RUN apt-get update \
# && apt-get install -y --no-install-recommends \
# creduce \
# gdb \
# libopus-dev \
# libsodium-dev \
# libvpx-dev \
# linux-libc-dev \
# musl-dev \
# && apt-get clean \
# && rm -rf /var/lib/apt/lists/*
#
#SHELL ["/bin/bash", "-o", "pipefail", "-c"]
#
#COPY --from=cake /src/workspace/cake/src/ /src/workspace/cake/src/
#
#WORKDIR /src/workspace/c-toxcore
#COPY . /src/workspace/c-toxcore/
#
#ENV CAKEFLAGS="-Wno-conditional-constant -D__x86_64__ -I/src/workspace/cake/src/include -I/src/workspace/cake/src -I/usr/include/x86_64-linux-musl -I/usr/include"
#
##RUN /src/workspace/cake/src/cake $CAKEFLAGS -E toxcore/DHT.c | grep -Ev '^(Cake|/| [01])' >crash.c
#RUN cp toxcore/test.c crash.c
#RUN other/docker/cake/creduce.sh
#RUN creduce other/docker/cake/creduce.sh crash.c \
# || creduce other/docker/cake/creduce.sh crash.c
#
#RUN gdb -ex r -ex bt --args /src/workspace/cake/src/cake -fanalyzer crash.c
