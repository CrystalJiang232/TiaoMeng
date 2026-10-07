#!/usr/bin/env python3
import argparse
import ctypes
import ctypes.util
import json
import socket
import struct
import time

from Crypto.Cipher import AES
from Crypto.Hash import SHA256

PUBLIC_KEY_SIZE = 1184
SECRET_KEY_SIZE = 2400
CIPHERTEXT_SIZE = 1088
SHARED_SECRET_SIZE = 32

NONCE_SIZE = 12
TAG_SIZE = 16

MSG_HANDSHAKE = 0x01
MSG_ENCRYPTED_REQUEST = 0x83
MSG_ENCRYPTED_RESPONSE = 0x84
MSG_ENCRYPTED_ERROR = 0x86

OQS_SUCCESS = 0


class Kyber768:
    def __init__(self, name="Kyber768"):
        path = ctypes.util.find_library("oqs") or "/usr/local/lib/liboqs.so"
        self._lib = ctypes.CDLL(path)
        self._lib.OQS_KEM_new.restype = ctypes.c_void_p
        self._lib.OQS_KEM_new.argtypes = [ctypes.c_char_p]
        self._lib.OQS_KEM_free.argtypes = [ctypes.c_void_p]
        self._lib.OQS_KEM_keypair.restype = ctypes.c_int
        self._lib.OQS_KEM_keypair.argtypes = [ctypes.c_void_p] * 3
        self._lib.OQS_KEM_encaps.restype = ctypes.c_int
        self._lib.OQS_KEM_encaps.argtypes = [ctypes.c_void_p] * 4
        self._lib.OQS_KEM_decaps.restype = ctypes.c_int
        self._lib.OQS_KEM_decaps.argtypes = [ctypes.c_void_p] * 4
        self._kem = self._lib.OQS_KEM_new(name.encode())
        if not self._kem:
            raise RuntimeError(f"OQS_KEM_new({name}) failed")

    def keypair(self):
        pk = ctypes.create_string_buffer(PUBLIC_KEY_SIZE)
        sk = ctypes.create_string_buffer(SECRET_KEY_SIZE)
        self._call("OQS_KEM_keypair", self._kem, pk, sk)
        return pk.raw, sk.raw

    def encapsulate(self, remote_pk):
        ct = ctypes.create_string_buffer(CIPHERTEXT_SIZE)
        ss = ctypes.create_string_buffer(SHARED_SECRET_SIZE)
        self._call("OQS_KEM_encaps", self._kem, ct, ss, ctypes.create_string_buffer(remote_pk))
        return ct.raw, ss.raw

    def decapsulate(self, ciphertext, secret_key):
        ss = ctypes.create_string_buffer(SHARED_SECRET_SIZE)
        self._call(
            "OQS_KEM_decaps", self._kem, ss, ctypes.create_string_buffer(ciphertext),
            ctypes.create_string_buffer(secret_key)
        )
        return ss.raw

    def _call(self, name, *args):
        if getattr(self._lib, name)(*args) != OQS_SUCCESS:
            raise RuntimeError(f"{name} failed")


def combine_secrets(secret_a, secret_b):
    digest = SHA256.new()
    digest.update(secret_a)
    digest.update(secret_b)
    return digest.digest()


class Session:
    def __init__(self, key):
        self._key = key
        self._counter = 0

    def encrypt(self, plaintext):
        nonce = b"\x00" * 4 + self._counter.to_bytes(8, "big")
        self._counter += 1
        ct, tag = AES.new(self._key, AES.MODE_GCM, nonce=nonce).encrypt_and_digest(plaintext)
        return nonce + ct + tag

    def decrypt(self, payload):
        cipher = AES.new(self._key, AES.MODE_GCM, nonce=payload[:NONCE_SIZE])
        return cipher.decrypt_and_verify(payload[NONCE_SIZE:-TAG_SIZE], payload[-TAG_SIZE:])


def send_msg(sock, msg_type, payload):
    sock.sendall(struct.pack(">I", len(payload) + 5) + bytes([msg_type]) + payload)


def recv_exact(sock, size):
    buf = b""
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def recv_msg(sock):
    length = struct.unpack(">I", recv_exact(sock, 4))[0]
    body = recv_exact(sock, length - 4)
    return body[0], body[1:]


class KyberClient:
    def __init__(self, host="127.0.0.1", port=8080):
        self._address = (host, port)
        self._kem = Kyber768()
        self._sock = None
        self._session = None

    def connect(self):
        self._sock = socket.create_connection(self._address, timeout=15)

    def close(self):
        if self._sock:
            self._sock.close()

    def handshake(self):
        pk, sk = self._kem.keypair()
        send_msg(self._sock, MSG_HANDSHAKE, pk)
        msg_type, payload = recv_msg(self._sock)
        if msg_type != MSG_HANDSHAKE or len(payload) != PUBLIC_KEY_SIZE + CIPHERTEXT_SIZE:
            raise RuntimeError(f"unexpected handshake response: {msg_type:#x} len={len(payload)}")
        server_pk, server_ct = payload[:PUBLIC_KEY_SIZE], payload[PUBLIC_KEY_SIZE:]
        ss_local = self._kem.decapsulate(server_ct, sk)
        client_ct, ss_remote = self._kem.encapsulate(server_pk)
        send_msg(self._sock, MSG_HANDSHAKE, client_ct)
        self._session = Session(combine_secrets(ss_remote, ss_local))
        return self._read()[1]

    def request(self, body):
        return self.send_encrypted(json.dumps(body).encode())

    def send_encrypted(self, plaintext):
        send_msg(self._sock, MSG_ENCRYPTED_REQUEST, self._session.encrypt(plaintext))
        return self._read()

    def send_raw(self, payload):
        send_msg(self._sock, MSG_ENCRYPTED_REQUEST, payload)
        return self._read()

    def is_closed(self):
        self._sock.settimeout(1.0)
        try:
            return self._sock.recv(1) == b""
        except TimeoutError:
            return False
        except OSError:
            return True

    def rekey(self):
        msg_type, start = self.request({"action": "rekey"})
        if start.get("status") != "RekeyStart":
            raise RuntimeError(f"rekey not started: {msg_type:#x} {start}")
        pk, sk = self._kem.keypair()
        send_msg(self._sock, MSG_HANDSHAKE, pk)
        msg_type, payload = recv_msg(self._sock)
        if msg_type != MSG_HANDSHAKE:
            raise RuntimeError(f"unexpected rekey response: {msg_type:#x}")
        server_pk, server_ct = payload[:PUBLIC_KEY_SIZE], payload[PUBLIC_KEY_SIZE:]
        ss_local = self._kem.decapsulate(server_ct, sk)
        client_ct, ss_remote = self._kem.encapsulate(server_pk)
        send_msg(self._sock, MSG_HANDSHAKE, client_ct)
        self._session = Session(combine_secrets(ss_remote, ss_local))
        return self._read()[1]

    def _read(self):
        msg_type, payload = recv_msg(self._sock)
        return msg_type, json.loads(self._session.decrypt(payload))


def check_failure_threshold(host, port, limit=5):
    client = KyberClient(host, port)
    client.connect()
    client.handshake()
    for _ in range(limit):
        msg_type, body = client.send_raw(b"\x00" * 32)
        if body.get("message") != "Decryption failed":
            raise SystemExit(f"unexpected failure response: {body}")
    if not client.is_closed():
        raise SystemExit("failure threshold not enforced")
    print(f"failure counter closed the connection after {limit} errors")


def run(host, port, lifetime, wait):
    client = KyberClient(host, port)
    client.connect()
    ready = client.handshake()
    print(f"handshake: {ready}")
    if ready.get("status") != "ConnectionReady":
        raise SystemExit("handshake failed")

    if wait:
        print(f"waiting {lifetime + 1}s for key expiry")
        time.sleep(lifetime + 1)

    msg_type, expired = client.request({"action": "broadcast", "message": "probe"})
    print(f"post-expiry request: {msg_type:#x} {expired}")
    if msg_type != MSG_ENCRYPTED_ERROR or expired.get("message") != "Key expired, rekeying required":
        raise SystemExit("expiry path not observed")

    complete = client.rekey()
    print(f"rekey: {complete}")
    if complete.get("status") != "RekeyComplete":
        raise SystemExit("rekey failed")

    msg_type, restored = client.request({"action": "broadcast", "message": "after"})
    print(f"post-rekey request: {msg_type:#x} {restored}")
    if restored.get("message") == "Key expired, rekeying required":
        raise SystemExit("key not restored after rekey")

    client.close()
    check_failure_threshold(host, port)
    print("OK")


def main():
    parser = argparse.ArgumentParser(description="Minimal Kyber768 client and rekey scenario")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--lifetime", type=int, default=30, help="server key_lifetime_sec")
    parser.add_argument("--no-wait", action="store_true", help="skip the expiry wait (rekey-on-demand only)")
    parser.add_argument("--threshold-only", action="store_true", help="run only the failure-counter check")
    args = parser.parse_args()
    if args.threshold_only:
        check_failure_threshold(args.host, args.port)
        return
    run(args.host, args.port, args.lifetime, not args.no_wait)


if __name__ == "__main__":
    main()
