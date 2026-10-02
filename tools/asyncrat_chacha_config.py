#!/usr/bin/env python3
"""Static config extractor for the AsyncRAT ChaCha20 fork seen in the fake NF-e phishing chain.

Reads the #US (user strings) heap of the extracted .NET client, finds the master key, derives the
32-byte ChaCha20 key and decrypts every config value. It never executes the sample and never writes
binaries to disk: the only output is JSON on stdout.

Usage:
    python asyncrat_chacha_config.py <extracted_client.dll>
    python asyncrat_chacha_config.py --key <master_key> <encrypted_b64> [<encrypted_b64> ...]

Requires: dnfile (pip install dnfile)
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import struct
import sys

B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
NONCE_LEN = 12
KEY_LEN = 32


def _rotl32(value: int, count: int) -> int:
    return ((value << count) & 0xFFFFFFFF) | (value >> (32 - count))


def _quarter_round(s: list[int], a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl32(s[b] ^ s[c], 7)


def chacha20_xor(key: bytes, nonce: bytes, data: bytes, counter: int = 1) -> bytes:
    """RFC 8439 ChaCha20 (20 rounds, 96-bit nonce). The malware starts the block counter at 1."""
    out = bytearray()
    for offset in range(0, len(data), 64):
        state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574,
                 *struct.unpack("<8I", key), counter, *struct.unpack("<3I", nonce)]
        work = state[:]
        for _ in range(10):
            _quarter_round(work, 0, 4, 8, 12); _quarter_round(work, 1, 5, 9, 13)
            _quarter_round(work, 2, 6, 10, 14); _quarter_round(work, 3, 7, 11, 15)
            _quarter_round(work, 0, 5, 10, 15); _quarter_round(work, 1, 6, 11, 12)
            _quarter_round(work, 2, 7, 8, 13); _quarter_round(work, 3, 4, 9, 14)
        keystream = struct.pack("<16I", *((w + s) & 0xFFFFFFFF for w, s in zip(work, state)))
        block = data[offset:offset + 64]
        out += bytes(x ^ y for x, y in zip(block, keystream))
        counter += 1
    return bytes(out)


def derive_key(master_key: str) -> bytes:
    """Fold the UTF-8 master key into 32 bytes: k[i%32] ^= b; k[(i+7)%32] += b."""
    key = bytearray(KEY_LEN)
    for i, byte in enumerate(master_key.encode("utf-8")):
        key[i % KEY_LEN] ^= byte
        key[(i + 7) % KEY_LEN] = (key[(i + 7) % KEY_LEN] + byte) & 0xFF
    return bytes(key)


def decrypt_value(key: bytes, value_b64: str) -> str | None:
    """Value layout: base64( nonce[12] || ciphertext ). Returns None if it is not valid UTF-8."""
    try:
        raw = base64.b64decode(value_b64, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) <= NONCE_LEN:
        return None
    try:
        return chacha20_xor(key, raw[:NONCE_LEN], raw[NONCE_LEN:]).decode("utf-8")
    except UnicodeDecodeError:
        return None


def b64_text(value: str) -> str | None:
    if len(value) < 4 or len(value) % 4 or not B64_RE.match(value):
        return None
    try:
        return base64.b64decode(value).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None


def read_user_strings(path: str) -> list[str]:
    import dnfile  # imported lazily so --key mode works without it

    heap = dnfile.dnPE(path).net.user_strings.__data__
    strings, offset = [], 1
    while offset < len(heap):
        first = heap[offset]
        if first & 0x80 == 0:
            header, size = 1, first
        elif first & 0xC0 == 0x80:
            header, size = 2, ((first & 0x3F) << 8) | heap[offset + 1]
        else:
            header = 4
            size = ((first & 0x1F) << 24) | (heap[offset + 1] << 16) | (heap[offset + 2] << 8) | heap[offset + 3]
        if size == 0:
            offset += 1
            continue
        raw = heap[offset + header:offset + header + size]
        strings.append(raw[:-1].decode("utf-16-le", "replace") if size % 2 else raw.decode("utf-16-le", "replace"))
        offset += header + size
    return strings


def extract(path: str) -> dict:
    # Layer 1: every literal is base64(UTF-8) and goes through Decrypt_Base64() at runtime.
    decoded = [d for d in (b64_text(s) for s in read_user_strings(path)) if d]
    # The master key is itself base64 of a 32-char ASCII string.
    candidates = [k for k in (b64_text(d) for d in decoded) if k and len(k) == KEY_LEN and k.isascii()]
    for master_key in candidates:
        key = derive_key(master_key)
        values = [v for v in (decrypt_value(key, d) for d in decoded if d != master_key) if v is not None]
        if values:
            return {"master_key": master_key, "decrypted_values": values}
    return {"error": "master key not found"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--key", help="master key (skips auto-detection)")
    parser.add_argument("inputs", nargs="+", help="client DLL, or encrypted base64 values when --key is set")
    args = parser.parse_args()

    if args.key:
        key = derive_key(args.key)
        result = {value: decrypt_value(key, value) for value in args.inputs}
    else:
        result = extract(args.inputs[0])
    json.dump(result, sys.stdout, ensure_ascii=False, indent=2)
    print()
    return 0 if "error" not in result else 1


if __name__ == "__main__":
    raise SystemExit(main())
