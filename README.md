> 七载寻梦悠迢迢，玲珑剑阁渡逍遥。

---

# TiaoMeng  

[![C++23](https://img.shields.io/badge/C++-23-blue.svg)](https://en.cppreference.com/w/cpp/23)
[![Boost](https://img.shields.io/badge/Boost-1.82+-orange.svg)](https://www.boost.org/)

A high-performance TCP messaging server implementing post-quantum cryptography (Kyber768 KEM) with C++20 coroutines, thread-per-core architecture, and comprehensive per-operation timeouts.

## Quick Start

### Prerequisites

- GCC 14+ or Clang 16+ (C++23 support required)
- CMake 3.25+
- Boost 1.82+ (system, json components)
- liboqs (Kyber768 support)
- OpenSSL 3.0+ (AES-GCM)

### Build

```bash
# Optimized production build, best performance  
cmake -DMSG_SVR_BUILD_MODE=OPTIMIZE -B build
cmake --build build -j$(nproc)

# Development build (default)
cmake -B build && cmake --build build -j$(nproc)

# Debug build with sanitizers
cmake -DMSG_SVR_BUILD_MODE=DEBUG -B build
cmake --build build -j$(nproc)

# Catch2-based unit test
cmake -DMSG_SVR_BUILD_MODE=TEST -B build
cmake --build build -j$(nproc)
```

### Run

Program accepts one CLI argument indicating listening port, defaults to 8080:  

```bash
# Default port (8080)
./build/bin/server

# Custom port
./build/bin/server 9090
```

On initialization, server loads `server_config.json` from working directory if present.

> Upon fatal read error or incorrect file format, default settings for ALL configurations will be loaded. Otherwise default value is used for single invalid/out-of-range configuration option.  

> CLI port settings override one specified in `server_config.json`.  


## Configuration

### server_config.json

```json
{
  "server": {
    "port": 8080,
    "bind_address": "0.0.0.0",
    "max_connections": 1000,
    "max_message_size": 1048576
  },
  "security": {
    "max_failures_before_disconnect": 5,
    "session_timeout_sec": 3600,
    "key_rotation_interval_sec": 86400,
    "require_client_auth": true
  },
  "timeouts": {
    "handshake_timeout_sec": 30,
    "read_timeout_sec": 30,
    "write_timeout_sec": 30
  },
  "logging": {
    "level": "info",
    "file": "",
    "max_size_mb": 100,
    "enable_console": true
  }
}
```

| Section | Key | Description | Default | Valid Range/Options |
|:-------:|:---:|-------------|:-------:|:-------------------:|
| server | port | Listen port | 8080 | 1-65535 |
| server | bind_address | Interface to bind | 0.0.0.0 | Valid IP address |
| server | max_connections | Connection limit | 1000 | 1-100000 |
| server | max_message_size | Max message payload | 1048576 | 1024-104857600 |
| security | max_failures_before_disconnect | Error threshold per connection | 5 | 1-100 |
| security | session_timeout_sec | Idle timeout after handshake | 3600 | 10-2592000 |
| security | key_rotation_interval_sec | Session key rotation interval | 86400 | 60-31536000 |
| security | require_client_auth | Require authentication | true | true/false |
| timeouts | handshake_timeout_sec | Handshake completion limit | 30 | 1-300 |
| timeouts | read_timeout_sec | Per-read operation limit | 30 | 1-3600 |
| timeouts | write_timeout_sec | Per-write operation limit | 30 | 1-300 |
| logging | level | Log verbosity level | info | debug/info/warn/error |
| logging | file | Log file path | "" | Valid path or empty |
| logging | max_size_mb | Max log file size | 100 | 1-10000 |
| logging | enable_console | Log to stdout | true | true/false |

## Architecture

```
                    ┌─────────────────┐
    Client ────────►│  Connection     │
                    │  (per-client)   │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
        ┌─────────┐   ┌──────────┐   ┌──────────┐
        │  Auth   │   │ Command  │   │ Broadcast│
        │ Handler │   │ Handler  │   │ Handler  │
        └─────────┘   └──────────┘   └──────────┘
```

### Protocol

Length-prefixed binary protocol with type flags:

```
[4 bytes: length] [1 byte: type] [payload]
```

- **Length**: Total message size (big-endian), max 1MB
- **Type**: Bit 7 = encrypted flag, Bits 3-0 = semantic
- **Semantic**: Control(0), Handshake(1), Session(2), Request(3), Response(4), Notify(5), Error(6)

Handshake flow uses Kyber768 KEM:
1. Client sends public key
2. Server responds with ephemeral public key + ciphertext
3. Client sends encapsulation ciphertext
4. Both derive shared session key via SHA256 combined secrets

### Concurrency Model

- **io_context-per-thread**: `hardware_concurrency()` threads
- **Strand-per-connection**: Serializes I/O operations per client
- **Shared mutex**: Read-heavy connection map access

## Key Features

| Feature | Implementation |
|:---------:|:---------------:|
| Post-Quantum Crypto | Kyber768 KEM + AES-GCM-256 |
| Async I/O | C++20 coroutines + Boost.Asio |
| Thread Safety | Strand-per-connection pattern |
| Timeouts | Per-operation (read/write) with `operator\|\|` pattern |
| Metrics | Atomic counters + SIGUSR1-triggered reporting |
| Protocol | Length-prefixed binary framing |
| State Machine | Connected → Handshaking → Established → Authenticated |

## Build Modes

| Mode | CMake Flag | Purpose | Key Flags |
|:------:|:-----------:|:---------:|:-----------:|
| DEFAULT | (none) | Development | -O2 -g |
| DEBUG | `-DMSG_SVR_BUILD_MODE=DEBUG` | Debugging | -O0 -fsanitize=address,undefined |
| OPTIMIZE | `-DMSG_SVR_BUILD_MODE=OPTIMIZE` | Production | -O3 -march=native -flto |
| TEST | `-DMSG_SVR_BUILD_MODE=TEST` | CI/Testing | -O2 + CTest integration |

## Unit Test

Unit tests use [Catch2 v3](https://github.com/catchorg/Catch2) framework and cover cryptographic primitives, configuration parsing, and message serialization.

### Build with Tests

```bash
cmake -DMSG_SVR_BUILD_MODE=TEST -B build
cmake --build build -j$(nproc)
```

### Run Tests

```bash
cd build && ctest --output-on-failure
```

Or run directly:
```bash
./build/tests/test_crypto
./build/tests/test_config
./build/tests/test_fundamentals
```

### Test Coverage

| Component | Test Cases |
|-----------|------------|
| **Crypto** | Kyber768 keypair generation, encapsulate/decapsulate, secret combining; AES-GCM encrypt/decrypt, tamper detection; SessionKey lifecycle |
| **Config** | Default values, JSON parsing, validation (ranges, types), partial config handling, error cases |
| **Fundamentals** | Byte conversion utilities, message serialization/deserialization, protocol constants, roundtrip integrity |

## Test Client

A test client implementation is provided for integration testing with full Kyber768 handshake and AES-GCM encryption support.

```bash
# Build test client
./build/bin/client <host> <port>
```

## Project Structure

```
├── include/               # Public headers
│   ├── server.hpp         # Server, Connection, metrics
│   ├── config.hpp         # JSON configuration
│   ├── crypto/            # Kyber768, AES-GCM, SessionKey
│   ├── fundamentals/      # Message types, serialization
│   └── ...
├── server/                # Server implementation
├── crypto/                # Cryptographic primitives
├── fundamentals/          # Core utilities
├── logger/                # spdlog wrapper
├── client/                # Test client
└── CMakeLists.txt         # Multi-mode build config
```

## Signals

| Signal | Action |
|:--------:|:--------:|
| SIGINT / SIGTERM | Graceful shutdown + print final metrics |  
| SIGUSR1 | Print current server metrics to stdout and log |  

## Performance

Load tested: 300+ concurrent connections, 100% handshake/auth success, ~10 req/s per connection sustained throughput.

## Tech Stack

- **C++23**: Coroutines, concepts, ranges, `std::expected`
- **Boost.Asio 1.82+**: Networking, strands, timers
- **liboqs**: NIST post-quantum cryptography (Kyber768) based bidirectional key exchange  
- **OpenSSL 3.0**: AES-GCM-256 encryption
- **spdlog**: Structured logging
- **CMake 3.25+**: Build system with mode selection

## TODO / Planned Features

- [ ] **Stable Session Timer**: Global per-connection timer for session lifetime management (currently disabled due to async_wait blocking issue)
- [ ] **Session Key Rotation**: Rekeying state implementation for long-lived connections
- [ ] **Connection Pooling**: Optimized broadcast delivery with connection reuse
- [ ] **Prometheus Metrics**: Export metrics in Prometheus format for monitoring
- [ ] **Docker Containerization**: Multi-stage Dockerfile for deployment
- [ ] **Configuration Hot-Reload**: Runtime configuration updates without restart
- [ ] **Rate Limiting**: Per-IP and per-connection request throttling

## Author

**[ Crystal ]** — CS Undergraduate  
Backend Development | Distributed Systems | Applied Cryptography

[GitHub](https://github.com/CrystalJiang232) | [Email](crystaljiang2023@126.com)
