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
RUN curl -L https://github.com/pizlonator/fil-c/releases/download/v0.687/filc-0.687-linux-x86_64.tar.xz \
 | tar xJ --strip-components=1 \
 && ./setup.sh
ENV CC=/work/filc/build/bin/clang CXX=/work/filc/build/bin/clang++

# Everything must be compiled with Fil-C, including our dependencies.
WORKDIR /work/libsodium
RUN curl -L https://github.com/jedisct1/libsodium/releases/download/1.0.20-RELEASE/libsodium-1.0.20.tar.gz \
 | tar xz --strip-components=1 \
 && ./configure --prefix=/work/prefix --disable-asm --disable-shared \
 && make -j"$(nproc)" install

WORKDIR /work/opus
RUN curl -L https://github.com/xiph/opus/releases/download/v1.5.2/opus-1.5.2.tar.gz \
 | tar xz --strip-components=1 \
 && ./configure --prefix=/work/prefix --disable-asm --disable-intrinsics --disable-rtcd --disable-shared \
 --disable-doc --disable-extra-programs \
 && make -j"$(nproc)" install

# Fil-C can't free a pointer that was stored as an integer, so we make libvpx store it as a pointer.
WORKDIR /work/libvpx
RUN curl -L https://github.com/webmproject/libvpx/archive/v1.15.0.tar.gz \
 | tar xz --strip-components=1 \
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
RUN curl -L https://github.com/google/googletest/releases/download/v1.17.0/googletest-1.17.0.tar.gz \
 | tar xz --strip-components=1 \
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
