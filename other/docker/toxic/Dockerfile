FROM ubuntu:20.04

RUN apt-get update && \
 DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends \
 ca-certificates \
 clang \
 cmake \
 git \
 libalut-dev \
 libconfig-dev \
 libcurl4-openssl-dev \
 libgtest-dev \
 libncursesw5-dev \
 libnotify-dev \
 libopenal-dev \
 libopus-dev \
 libpng-dev \
 libqrencode-dev \
 libsodium-dev \
 libvpx-dev \
 libx11-dev \
 make \
 ninja-build \
 pkg-config \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /home/builder
RUN groupadd -r -g 1000 builder \
 && useradd --no-log-init -r -g builder -u 1000 builder \
 && chown builder:builder /home/builder
USER builder

ENV CC=clang CXX=clang++ USER=builder

COPY --chown=builder:builder . /home/builder/c-toxcore
WORKDIR /home/builder/c-toxcore
RUN ["cmake", "-B_build", "-H.", "-GNinja"]
RUN ["cmake", "--build", "_build"]
USER root
RUN ["cmake", "--build", "_build", "--target", "install"]
USER builder

RUN ["git", "clone", "https://github.com/TokTok/toxic", "/home/builder/toxic"]
WORKDIR /home/builder/toxic
RUN ["make"]
USER root
RUN ["make", "install"]
USER builder
