FROM ubuntu:22.04

RUN apt-get update && \
 DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends \
 ca-certificates \
 cmake \
 curl \
 gcc \
 g++ \
 libconfig-dev \
 libopus-dev \
 libsodium-dev \
 libvpx-dev \
 ninja-build \
 strace \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

RUN curl -o pvs-studio.deb https://cdn.pvs-studio.com/pvs-studio-7.29.79138.387-amd64.deb \
 && dpkg -i pvs-studio.deb \
 && rm pvs-studio.deb
ARG LICENSE_USER="iphydf@gmail.com" LICENSE_KEY=""
RUN pvs-studio-analyzer credentials "$LICENSE_USER" "$LICENSE_KEY"

WORKDIR /work/c-toxcore
COPY . /work/c-toxcore/

RUN cmake . -B_build -GNinja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DENABLE_SHARED=OFF

# MISRA
RUN echo 'analysis-mode=32' > pvs.cfg
RUN pvs-studio-analyzer analyze --cfg pvs.cfg -f _build/compile_commands.json -j"$(nproc)" -o misra.log

# General Analysis
RUN echo 'analysis-mode=0' > pvs.cfg
RUN pvs-studio-analyzer analyze --cfg pvs.cfg -f _build/compile_commands.json -j"$(nproc)" -o pvs.log

# Show MISRA errors
RUN plog-converter \
  -E "other;testing;toxav;third_party" \
  -d "V2501,V2511,V2514,V2516,V2519,V2520,V2537,V2547,V2568,V2571,V2572,V2575,V2578,V2594,V2611,V2614,V2620" \
  -a "MISRA:1,2" \
  -t "tasklist" \
  -o "misra.tasks" \
  "misra.log"
RUN cat misra.tasks

# Show MISRA errors
RUN plog-converter \
  -E "other;testing;toxav;third_party" \
  -d "V501,V547,V641,V802,V1037,V1042,V1051,V1086" \
  -a "GA:1,2,3;OP:1,2,3" \
  -t "tasklist" \
  -o "pvs.tasks" \
  "pvs.log"
RUN cat pvs.tasks
