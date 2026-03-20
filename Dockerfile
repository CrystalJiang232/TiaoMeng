# syntax=docker/dockerfile:1

FROM ubuntu:24.04 AS builder

RUN apt-get update && apt-get install -y \
    g++-14 cmake ninja-build \
    libboost-all-dev libssl-dev libsqlite3-dev libsodium-dev \
    git python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

# liboqs partition

ARG LIBOQS_VERSION=0.12.0
RUN git config --global url."https://bgithub.xyz".insteadOf "https://github.com" && git clone --depth 1 --branch ${LIBOQS_VERSION} https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
    && cmake -S /tmp/liboqs -B /tmp/liboqs/build \
       -DCMAKE_BUILD_TYPE=Release \
       -DBUILD_SHARED_LIBS=ON \
       -DOQS_BUILD_ONLY_LIB=ON \
    && cmake --build /tmp/liboqs/build -j$(nproc) \
    && cmake --install /tmp/liboqs/build \
    && ldconfig \
    && rm -rf /tmp/liboqs

# COPY /docker_lib/liboqs.so /usr/local/lib/
# COPY /docker_lib/oqs /usr/local/include/oqs
# RUN ldconfig

WORKDIR /src
COPY . .

ENV CXX=g++-14
RUN cmake -B build \
    -DMSG_SVR_BUILD_MODE=OPTIMIZE \
    -DCMAKE_BUILD_TYPE=Release \
    -G Ninja \
    && cmake --build build -j$(nproc)

FROM ubuntu:24.04 AS runtime

RUN apt-get update && apt-get install -y \
    libboost-json-dev libssl3 libsqlite3-0 libsodium-dev netcat-traditional \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /bin/false hibiscus

COPY --from=builder /usr/local/lib/liboqs.so* /usr/local/lib/
RUN ldconfig

COPY --from=builder /src/build/bin/server /usr/local/bin/
COPY --from=builder /src/build/bin/user_admin /usr/local/bin/
COPY docker-entrypoint.sh /etc/tiaomeng/

RUN chown -R hibiscus:hibiscus /etc/tiaomeng \
    && chmod +x /etc/tiaomeng/docker-entrypoint.sh

USER hibiscus
WORKDIR /etc/tiaomeng

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD nc -z localhost 8080 || exit 1

ENTRYPOINT ["/etc/tiaomeng/docker-entrypoint.sh"]
CMD ["server"]
