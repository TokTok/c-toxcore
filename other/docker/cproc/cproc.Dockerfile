FROM toxchat/c-toxcore:sources AS sources
FROM ubuntu:22.04

RUN apt-get update && \
 DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends \
 ca-certificates \
 creduce \
 gcc \
 git \
 libc-dev \
 libopus-dev \
 libsodium-dev \
 libvpx-dev \
 make \
 pkg-config \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

RUN git config --global user.email "you@example.com"
RUN git config --global user.name "Your Name"

WORKDIR /work/qbe
RUN ["git", "clone", "--depth=1", "git://c9x.me/qbe.git", "/work/qbe"]
RUN ["make", "install", "CFLAGS=-O3 -std=c99"]

WORKDIR /work/cproc
RUN ["git", "clone", "https://github.com/michaelforney/cproc", "/work/cproc"]
# https://todo.sr.ht/~mcf/cproc/79
RUN ["git", "revert", "b82a231"]
RUN ./configure && make install

WORKDIR /work/c-toxcore
COPY --from=sources /src/ /work/c-toxcore
COPY other/docker/cproc/Makefile other/docker/cproc/alloca.c /work/c-toxcore/
RUN ["make"]

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN ./send_message_test | grep "tox clients connected"

# If cproc crashes, make a repro with this:
#COPY other/docker/cproc/creduce.sh /work/c-toxcore
#RUN cproc -E -o broken.c auto_tests/auto_test_support.c
#RUN creduce ./creduce.sh broken.c
