FROM toxchat/c-toxcore:sources AS src
FROM golang:1.18-alpine AS build

ENV LANG=en_US.UTF-8 \
    LANGUAGE=en_US.UTF-8 \
    LC_CTYPE=en_US.UTF-8 \
    LC_ALL=en_US.UTF-8

RUN ["go", "install", "github.com/google/pprof@latest"]
RUN ["apk", "add", "--no-cache", \
 "--repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing/", \
 "binutils", \
 "clang", \
 "cmake", \
 "gcc", \
 "gperftools-dev", \
 "graphviz", \
 "libsodium-dev", \
 "libvpx-dev", \
 "linux-headers", \
 "musl-dev", \
 "opus-dev", \
 "pkgconfig", \
 "samurai"]
WORKDIR /work
COPY --from=src /src/ /work/
RUN cmake -B_build -H. -GNinja -DAUTOTEST=ON -DENABLE_SHARED=OFF -DENABLE_PROFILING=ON -DCMAKE_EXE_LINKER_FLAGS="-dynamic"
RUN cmake --build _build
RUN CPUPROFILE_FREQUENCY=4000 \
    CPUPROFILE=auto_test.prof \
    _build/auto_tests/auto_send_message_test

ENV PPROF_BINARY_PATH=/work/_build/auto_tests
CMD ["pprof", "-http", "0.0.0.0:80", "_build/auto_tests/auto_send_message_test", "auto_test.prof"]
