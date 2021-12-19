# c-toxcore Clusterfuzzlite build environment

# We want to use the latest tools always
# hadolint ignore=DL3006
FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && \
    apt-get -y install --no-install-suggests --no-install-recommends \
    cmake libtool autoconf automake pkg-config

RUN git clone --depth 1 --branch 1.0.18 https://github.com/jedisct1/libsodium libsodium
WORKDIR libsodium
RUN ./autogen.sh && ./configure --enable-shared=no && make install

# Copy your project's source code.
COPY . $SRC/c-toxcore
# Working directory for build.sh.
WORKDIR $SRC/c-toxcore
# Copy build.sh into $SRC dir.
COPY ./.clusterfuzzlite/build.sh $SRC/
