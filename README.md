> 七载寻梦悠迢迢，玲珑剑阁渡逍遥。

---

# TiaoMeng

[![C++23](https://img.shields.io/badge/C++-23-blue.svg)](https://en.cppreference.com/w/cpp/23)
[![Boost](https://img.shields.io/badge/Boost-1.82+-orange.svg)](https://www.boost.org/)
[![liboqs](https://img.shields.io/badge/liboqs-0.12.0-green.svg)](https://github.com/open-quantum-safe/liboqs)

A high-performance TCP messaging server implementing post-quantum cryptography (Kyber768 KEM) with C++23 coroutines, thread-per-core architecture, and comprehensive per-operation timeouts.

## Quick Start

### Prerequisites

- GCC 14+ or Clang 16+ (C++23 support required)
- CMake 3.25+
- Boost 1.82+ (system, json components)
- liboqs 0.12.0 (Kyber768 support)
- OpenSSL 3.0+ (AES-GCM)
- SQLite3
- libsodium (Argon2id)

### Installing Dependencies

```bash
# Ubuntu/Debian
sudo apt-get install g++-14 cmake ninja-build \
    libboost-all-dev libssl-dev libsqlite3-dev libsodium-dev

# liboqs (Kyber768 support)
git clone --depth 1 --branch 0.12.0 https://github.com/open-quantum-safe/liboqs.git
cmake -S liboqs -B liboqs/build -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON
sudo cmake --build liboqs/build -j$(nproc) && sudo cmake --install liboqs/build
sudo ldconfig
```

### Build

```bash
# Optimized production build
cmake -DMSG_SVR_BUILD_MODE=OPTIMIZE -B build
cmake --build build -j$(nproc)

# Development build (default)
cmake -B build && cmake --build build -j$(nproc)

# Debug build with sanitizers
cmake -DMSG_SVR_BUILD_MODE=DEBUG -B build
cmake --build build -j$(nproc)

# Build with tests
cmake -DMSG_SVR_BUILD_MODE=TEST -B build
cmake --build build -j$(nproc)
```

### Run

```bash
# Default port (8080) - uses server_config.json if present
./build/bin/server

# Custom port (overrides config file)
./build/bin/server 9090
```

Configuration loading rules:
1. If `server_config.json` exists and is valid, load it
2. If file missing or invalid format, use ALL defaults
3. If individual values invalid/out-of-range, use default for that value only
4. CLI port argument overrides config file

## Configuration

### server_config.json

```json
{
  "server": {
    "port": 8080,
    "bind_address": "0.0.0.0",
    "max_connections": 1000,
    "max_message_size": 1048576,
    "io_threads": 20
  },
  "security": {
    "max_failures_before_disconnect": 5,
    "session_timeout_sec": 3600,
    "key_rotation_interval_sec": 86400,
    "require_client_auth": false
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

### Configuration Options

| Section  |              Key               | Description            | Default |      Valid Range      |
| :------: | :----------------------------: | ---------------------- | :-----: | :-------------------: |
|  server  |              port              | Listen port            |  8080   |        1-65535        |
|  server  |          bind_address          | Interface to bind      | 0.0.0.0 |   Valid IP address    |
|  server  |        max_connections         | Connection limit       |  1000   |       1-100000        |
|  server  |        max_message_size        | Max message payload    | 1048576 |    1024-104857600     |
|  server  |           io_threads           | I/O thread pool size   |   20    |   1-hardware limit    |
| security | max_failures_before_disconnect | Error threshold        |    5    |         1-100         |
| security |      session_timeout_sec       | Idle timeout           |  3600   |      10-2592000       |
| security |   key_rotation_interval_sec    | Key rotation interval  |  86400  |      60-31536000      |
| security |      require_client_auth       | Require authentication |  false  |      true/false       |
| timeouts |     handshake_timeout_sec      | Handshake limit        |   30    |         1-300         |
| timeouts |        read_timeout_sec        | Per-read limit         |   30    |        1-3600         |
| timeouts |       write_timeout_sec        | Per-write limit        |   30    |         1-300         |
| logging  |             level              | Log verbosity          |  info   | debug/info/warn/error |
| logging  |              file              | Log file path          |   ""    |  Valid path or empty  |
| logging  |          max_size_mb           | Max log file size      |   100   |        1-10000        |
| logging  |         enable_console         | Log to stdout          |  true   |      true/false       |

## Docker

Build is self-contained with multi-stage Dockerfile.

```bash
# Build image
docker build -t tiaomeng:latest .

# Run with auto-created admin user
docker run -d -p 8080:8080 -e ADMIN_USER=admin -e ADMIN_PASS=secret123 tiaomeng:latest

# Run with persistent auth database
docker run -d -p 8080:8080 -v $(pwd)/data:/etc/tiaomeng tiaomeng:latest
```

## User Administration

The auth database (`auth.db`) must be initialized before first use.

### Database Initialization

```bash
# Initialize schema only
./build/bin/user_admin init

# Initialize with bootstrap admin user
./build/bin/user_admin init <admin_username> <admin_password>
```

### Management Commands

```bash
# Add user
./build/bin/user_admin add <username> <password>

# List users
./build/bin/user_admin list

# Disable/Enable user
./build/bin/user_admin disable <username>
./build/bin/user_admin enable <username>

# Reset password
./build/bin/user_admin reset <username> <new_password>

# Kick user (clear connection)
./build/bin/user_admin kick <username>

# Delete user permanently
./build/bin/user_admin remove <username>

# Check database exists
./build/bin/user_admin exists
```

### Docker Usage

```bash
docker exec <container> user_admin <command> [args]
```

## Architecture

### High-Level Overview

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

### Connection State Machine

```
┌───────────┐    ┌────────────┐    ┌────────────┐    ┌────────────────┐
│ Connected │───►│ Handshaking│───►│ Established│───►│  Authenticated │
└───────────┘    └─────┬──────┘    └─────┬──────┘    └────────┬───────┘
                       │                 │                    │
                       ▼                 ▼                    ▼
                 ┌──────────┐      ┌──────────┐         ┌──────────┐
                 │ Closing  │◄─────│ Closing  │◄────────│ Closing  │
                 └──────────┘      └──────────┘         └──────────┘
```

States:
- **Connected**: Initial TCP accept, awaiting handshake initiation
- **Handshaking**: Kyber768 key exchange in progress
- **Established**: Session key derived, encrypted channel active
- **Authenticated**: User successfully authenticated via Argon2id
- **Closing**: Connection termination in progress

State transitions use `std::atomic<ConnState>` with acquire-release memory ordering for thread safety.

### Protocol Specification

#### Binary Message Format

```
[4 bytes: length] [1 byte: type] [payload]
```

- **Length**: Total message size (big-endian), max 1MB (configurable)
- **Type**: Bit flags - Bit 7 = encrypted, Bits 3-0 = semantic
- **Payload**: Variable-length data

#### Message Type Flags

```cpp
// Bit 7: Encrypted flag
constexpr MsgType encrypted_flag = 0x80;

// Bits 3-0: Semantic
enum class MsgSemantic : uint8_t {
    Control   = 0x00,  // Connection control
    Handshake = 0x01,  // Key exchange (plaintext only)
    Session   = 0x02,  // Session management
    Request   = 0x03,  // Client request
    Response  = 0x04,  // Server response
    Notify    = 0x05,  // Server notification
    Error     = 0x06,  // Error message
};
```

| Constant              | Value | Usage                            |
| --------------------- | ----- | -------------------------------- |
| `plaintext_handshake` | 0x01  | Kyber768 key exchange            |
| `plaintext_error`     | 0x06  | Unencrypted errors               |
| `encrypted_request`   | 0x83  | Client requests (post-handshake) |
| `encrypted_response`  | 0x84  | Server responses                 |
| `encrypted_notify`    | 0x85  | Broadcast notifications          |
| `encrypted_error`     | 0x86  | Encrypted error responses        |

#### Kyber768 Handshake Flow

```
Client                                          Server
  │                                                │
  │── PLAINTEXT_HANDSHAKE (client_pk, 1184B) ────►│
  │                                                │
  │◄── PLAINTEXT_HANDSHAKE (server_pk, 1184B) ────│
  │                (server_ct, 1088B)              │
  │                                                │
  │── PLAINTEXT_HANDSHAKE (client_ct, 1088B) ────►│
  │                                                │
  │◄── ENCRYPTED_RESPONSE ("ConnectionReady") ────│
  │                                                │
  │                                                │
  │  [K = SHA256(client_secret || server_secret)]  │
  │                                                │
  │══════════════ SECURE CHANNEL ══════════════════│
```

1. Client generates Kyber768 keypair, sends public key (`pk_c`)
2. Server generates ephemeral keypair, encapsulates secret with `pk_c`, responds with `pk_s` + ciphertext
3. Client decapsulates server secret, encapsulates client secret with `pk_s`, sends ciphertext
4. Both derive 32-byte AES-GCM key via SHA256 of concatenated secrets

#### Post-Handshake Actions

| Action    | JSON Format                                           | Description              |
| --------- | ----------------------------------------------------- | ------------------------ |
| auth      | `{"action":"auth","username":"...","password":"..."}` | Authenticate user        |
| command   | `{"action":"command","cmd":"..."}`                    | Execute command          |
| broadcast | `{"action":"broadcast","message":"..."}`              | Broadcast to all clients |
| logout    | `{"action":"logout"}`                                 | Logout current user      |

### Concurrency Model

#### Thread-Per-Core I/O

- **I/O Threads**: `io_threads` count (default 20), each with dedicated `io_context`
- **CPU Affinity**: Threads pinned to specific cores via conditional compilation
  - Linux: `pthread_setaffinity_np` with `CPU_SET`
  - Windows: `SetThreadAffinityMask`
  - macOS: Not supported (placeholder)
- **Cache Optimization**: Connection data uses `alignas(64)` to prevent false sharing

#### Strand-Per-Connection

Each connection operates within a `boost::asio::strand`, providing:
- **Lock-free serialization**: Operations execute sequentially without explicit mutex
- **Implicit ordering**: No data races on connection state
- **Optimal performance**: Zero mutex overhead for per-connection operations

#### Write Queue Mechanism

Dual-locking strategy for thread-safe write operations:
- **`write_mtx`**: Protects access to `write_queue` (message buffering)
- **`write_in_progress`**: Atomic flag prevents spawning multiple write coroutines

Write flow: `send()` → enqueue → (if not writing) spawn `write()` coroutine → `write_with_timeout()` loop

### Error Handling

#### Fatal vs Non-Fatal Errors

| Category      | Examples                                                            | Action                        |
| ------------- | ------------------------------------------------------------------- | ----------------------------- |
| **Fatal**     | Read/write timeout, socket error codes, length verification failure | Immediate disconnect          |
| **Non-fatal** | Invalid message semantics, JSON parse error, decryption failure     | Send error response, continue |

#### Error Relay Chain

```
send_error() [encrypted]     send_raw_error() [plaintext]
        │                           │
        └───────────┬───────────────┘
                    ▼
               close()
                    │
                    ▼
              close_async()
```

- `send_error()`: Sends encrypted JSON error, optionally failure-tolerant
- `send_raw_error()`: Sends plaintext error, non-failure-tolerant
- All closures must go through error interface (not direct `close()` calls)

#### CloseMode

| Mode         | Behavior                                   |
| ------------ | ------------------------------------------ |
| **Graceful** | Drain write queue before socket shutdown   |
| **Abort**    | Cancel pending operations, immediate close |

Selection: Prefer `Graceful`; use `Abort` for fatal errors or write timeouts.

## Key Features

| Feature             | Implementation                                |
| :------------------ | :-------------------------------------------- |
| Post-Quantum Crypto | Kyber768 KEM (NIST standard) + AES-GCM-256    |
| Async I/O           | C++20 coroutines + Boost.Asio 1.82+           |
| Concurrency         | Thread-per-core with CPU affinity             |
| Thread Safety       | Strand-per-connection (lock-free)             |
| Timeouts            | Per-operation with `operator\|\|` pattern     |
| Authentication      | Argon2id (libsodium) + SQLite3                |
| Protocol            | Binary length-prefixed framing                |
| State Machine       | `std::atomic<ConnState>` with acquire-release |
| Cache Optimization  | `alignas(64)` for connection data             |
| Error Handling      | `std::expected` + `[[nodiscard]]` contracts   |
| Logging             | Custom level-based logger with metrics        |

## Build Modes

|   Mode   |           CMake Flag            |   Purpose    |               Key Flags                |
| :------: | :-----------------------------: | :----------: | :------------------------------------: |
| DEFAULT  |             (none)              | Development  |         `-O2 -g -Wall -Wextra`         |
|  DEBUG   |  `-DMSG_SVR_BUILD_MODE=DEBUG`   |  Debugging   | `-O0 -g3 -fsanitize=address,undefined` |
| OPTIMIZE | `-DMSG_SVR_BUILD_MODE=OPTIMIZE` |  Production  |       `-O3 -march=native -flto`        |
|   TEST   |   `-DMSG_SVR_BUILD_MODE=TEST`   | Unit testing |           `-O2 -g` + Catch2            |

## Testing

### Unit Tests (Catch2)

```bash
# Build with tests
cmake -DMSG_SVR_BUILD_MODE=TEST -B build
cmake --build build -j$(nproc)

# Run all tests
cd build && ctest --output-on-failure

# Run individual suites
./build/tests/test_crypto
./build/tests/test_config
./build/tests/test_fundamentals
```

**Coverage:**
- **Crypto**: Kyber768 keygen/encaps/decaps, AES-GCM encrypt/decrypt, tamper detection
- **Config**: JSON parsing, validation, defaults, error cases
- **Fundamentals**: Byte conversion, message serialization, protocol constants

### Integration Tests

Python-based integration tests in `pytest/`:
- `kyber_client.py`: Full client with handshake implementation
- `load_test.py`: Concurrent connection and throughput testing

## Project Structure

```
├── include/                    # Public headers
│   ├── server.hpp              # Server, Connection classes
│   ├── config.hpp              # Configuration parsing
│   ├── event_handler.hpp       # Request routing
│   ├── extern/CLI11/           # Bundled CLI11 library
│   ├── auth/                   # Authentication components
│   ├── crypto/                 # Kyber768, AES-GCM primitives
│   ├── fundamentals/           # Message types, serialization
│   ├── iocore/                 # I/O context pool, platform code
│   ├── logger/                 # Logger and metrics
│   ├── threadpool/             # CPU task pool
│   └── tools/                  # Admin utilities header
│
├── server/                     # Server implementation
├── crypto/                     # Cryptographic implementations
├── auth/                       # Authentication implementation
├── fundamentals/               # Core utilities
├── iocore/                     # I/O core implementation
├── logger/                     # Logging implementation
├── threadpool/                 # Thread pool implementation
├── tools/                      # User admin CLI
├── tests/                      # Catch2 unit tests
├── pytest/                     # Python integration tests
├── CMakeLists.txt              # Root build config
├── server_config.json          # Runtime configuration
└── Dockerfile                  # Multi-stage container build
```

## Signals

|      Signal      | Action                                         |
| :--------------: | :--------------------------------------------- |
| SIGINT / SIGTERM | Graceful shutdown + print final metrics        |
|     SIGUSR1      | Print current server metrics to stdout and log |

Metrics output includes: uptime, connections (accepted/closed/active), handshakes (completed/failed), authentication (success/failed), messages (received/sent/rate), bandwidth (rx/tx/total), errors, timeouts.

## Performance

Load tested with C++ client implementation:
- **300+ concurrent connections**: Stable handshake/auth success
- **1000+ req/s**: Sustained throughput
- **0 errors/resource leaks**: Verified under stress

Scalability characteristics:
- Linear scaling with `io_threads` up to physical core count
- Minimal context switching via CPU affinity
- Lock-free per-connection operations via strands

## Tech Stack

|      Component      |           Technology           |
| :-----------------: | :----------------------------: |
|      Language       |  C++23 (GCC 14+ / Clang 16+)   |
|    Build System     |          CMake 3.25+           |
|     Networking      |        Boost.Asio 1.82+        |
|        JSON         |           Boost.JSON           |
| Post-Quantum Crypto |    liboqs 0.12.0 (Kyber768)    |
|  Symmetric Crypto   |   OpenSSL 3.0+ (AES-GCM-256)   |
|   Authentication    | libsodium (Argon2id) + SQLite3 |
|     CLI Parsing     |        CLI11 (bundled)         |
|       Testing       |           Catch2 v3            |

## Known Limitations

- **Session Timer**: Per-connection session lifetime management currently disabled due to `async_wait` blocking issues
- **Session Key Rotation**: Rekeying state for long-lived connections planned
- **Prometheus Metrics**: Export in Prometheus format planned
- **Configuration Hot-Reload**: Runtime config updates without restart planned
- **Rate Limiting**: Per-IP and per-connection throttling planned

## Author

**[Crystal](https://github.com/CrystalJiang232)** — CS Undergraduate  
