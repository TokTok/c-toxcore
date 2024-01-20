################################################
# autotools-linux
FROM ubuntu:20.04

RUN apt-get update && \
 DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends \
 binutils \
 ca-certificates \
 g++ \
 libelf1 \
 libconfig-dev \
 libopus-dev \
 libsodium-dev \
 libvpx-dev \
 pkg-config \
 wget \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

RUN wget https://www.circle-lang.org/linux/build_200.tgz \
 && tar xvf build_200.tgz -C /usr/bin \
 && chmod +x /usr/bin/circle \
 && rm build_200.tgz

RUN groupadd -r -g 1000 builder \
 && useradd -m --no-log-init -r -g builder -u 1000 builder
USER builder

WORKDIR /home/builder

# Copy the sources and run the build.
COPY --chown=builder:builder auto_tests/ /home/builder/c-toxcore/auto_tests/
COPY --chown=builder:builder testing/ /home/builder/c-toxcore/testing/
COPY --chown=builder:builder third_party/ /home/builder/c-toxcore/third_party/
COPY --chown=builder:builder toxcore/ /home/builder/c-toxcore/toxcore/
COPY --chown=builder:builder toxencryptsave/ /home/builder/c-toxcore/toxencryptsave/
WORKDIR /home/builder/c-toxcore
RUN for i in \
 auto_tests/auto_test_support.c \
 auto_tests/send_message_test.c \
 testing/misc_tools.c \
 toxcore/*.c \
 toxcore/*/*.c \
 third_party/cmp/cmp.c; do \
   echo "$i"; \
   mv "$i" "${i}c"; \
   circle -c "${i}c" -o "${i}.o"; \
 done
# Circle segfaults on this file.
RUN g++ auto_tests/auto_test_support.cc -c
RUN circle -o send_message_test $(find . -name "*.o") $(pkg-config --libs libsodium) -lpthread
RUN ./send_message_test

# Enable this to make reproducing samples for circle compiler segfaults above.

#USER root
#RUN apt-get update && \
# DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends \
# creduce \
# && apt-get clean \
# && rm -rf /var/lib/apt/lists/*

#COPY other/docker/circle/circle-crash.sh /home/builder/c-toxcore/
#RUN circle -E auto_tests/auto_test_support.cc > crash.cc
#RUN ./circle-crash.sh
#RUN creduce circle-crash.sh crash.cc
#RUN cat crash.cc && false
