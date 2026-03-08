# syntax=docker/dockerfile:1

FROM ubuntu:24.04 AS builder

RUN apt-get update && apt-get install -y \
    g++-14 cmake ninja-build \
    libboost-all-dev libssl-dev libsqlite3-dev libsodium-dev \
    && rm -rf /var/lib/apt/lists/*

COPY /docker_lib/liboqs.so /usr/local/lib/
COPY /docker_lib/oqs /usr/local/include/oqs
RUN ldconfig

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
