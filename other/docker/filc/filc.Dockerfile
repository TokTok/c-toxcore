FROM toxchat/c-toxcore:sources AS sources
FROM ubuntu:24.04

RUN apt-get update && \
 DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends \
 binutils \
 ca-certificates \
 cmake \
 curl \
 linux-libc-dev \
 make \
 patchelf \
 perl \
 pkg-config \
 xz-utils \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

WORKDIR /work/filc
RUN curl -fsSLo filc.tar.xz https://github.com/pizlonator/fil-c/releases/download/v0.687/filc-0.687-linux-x86_64.tar.xz \
 && echo "aab538401f78a47ab261ee79afed8c6b99e1d4848e263ae159a75b03c1288da1  filc.tar.xz" | sha256sum -c \
 && tar xJf filc.tar.xz --strip-components=1 \
 && rm filc.tar.xz \
 && ./setup.sh
ENV CC=/work/filc/build/bin/clang CXX=/work/filc/build/bin/clang++

# Everything must be compiled with Fil-C, including our dependencies.
WORKDIR /work/libsodium
RUN curl -fsSLo libsodium.tar.gz https://github.com/jedisct1/libsodium/releases/download/1.0.22-RELEASE/libsodium-1.0.22.tar.gz \
 && echo "adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349  libsodium.tar.gz" | sha256sum -c \
 && tar xzf libsodium.tar.gz --strip-components=1 \
 && rm libsodium.tar.gz \
 && ./configure --prefix=/work/prefix --disable-asm --disable-shared \
 && make -j"$(nproc)" install

WORKDIR /work/opus
RUN curl -fsSLo opus.tar.gz https://downloads.xiph.org/releases/opus/opus-1.6.1.tar.gz \
 && echo "6ffcb593207be92584df15b32466ed64bbec99109f007c82205f0194572411a1  opus.tar.gz" | sha256sum -c \
 && tar xzf opus.tar.gz --strip-components=1 \
 && rm opus.tar.gz \
 && ./configure --prefix=/work/prefix --disable-asm --disable-intrinsics --disable-rtcd --disable-shared \
 --disable-doc --disable-extra-programs \
 && make -j"$(nproc)" install

# Fil-C can't free a pointer that was stored as an integer, so we make libvpx store it as a pointer.
WORKDIR /work/libvpx
RUN curl -fsSLo libvpx.tar.gz https://storage.googleapis.com/downloads.webmproject.org/releases/webm/libvpx-1.17.0.tar.gz \
 && echo "7f98aae5c52c46e85b7b26feabcab9b1554605e771bd1df1d6e6a00ee22fa8ed  libvpx.tar.gz" | sha256sum -c \
 && tar xzf libvpx.tar.gz --strip-components=1 \
 && rm libvpx.tar.gz \
 && sed -i \
 -e 's/size_t \*get_malloc_address_location/void **get_malloc_address_location/' \
 -e 's/return ((size_t \*)mem) - 1;/return ((void **)mem) - 1;/' \
 -e 's/size_t \*const malloc_addr_location/void **const malloc_addr_location/' \
 -e 's/= (size_t)malloc_addr;/= (void *)malloc_addr;/' \
 vpx_mem/vpx_mem.c \
 && LD="$CC" ./configure --prefix=/work/prefix --target=generic-gnu --disable-vp9 --disable-examples \
 --disable-tools --disable-docs --disable-unit-tests \
 && make -j"$(nproc)" install

WORKDIR /work/googletest
RUN curl -fsSLo googletest.tar.gz https://github.com/google/googletest/releases/download/v1.18.0/googletest-1.18.0.tar.gz \
 && echo "6e3191c1455468b3fc35a417fb565c1c5071aee1b7e7f85e30cf48a98d37d8b5  googletest.tar.gz" | sha256sum -c \
 && tar xzf googletest.tar.gz --strip-components=1 \
 && rm googletest.tar.gz \
 && cmake -B _build -DCMAKE_INSTALL_PREFIX=/work/prefix -DCMAKE_BUILD_TYPE=Release \
 && cmake --build _build -j"$(nproc)" --target install

WORKDIR /work/c-toxcore
COPY --from=sources /src/ /work/c-toxcore
RUN cmake -B _build -DCMAKE_PREFIX_PATH=/work/prefix -DCMAKE_BUILD_TYPE=RelWithDebInfo \
 -DENABLE_SHARED=OFF -DMUST_BUILD_TOXAV=ON -DAUTOTEST=ON -DBOOTSTRAP_DAEMON=OFF \
 && cmake --build _build -j"$(nproc)"
RUN ctest --test-dir _build -j"$(nproc)" --output-on-failure

RUN "$CC" -O2 -g -o locked_secrets_test other/docker/filc/locked_secrets_test.c \
 _build/libtoxcore.a $(PKG_CONFIG_PATH=/work/prefix/lib/pkgconfig pkg-config --static --libs libsodium opus vpx) \
 && ./locked_secrets_test
