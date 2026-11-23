"""Bit-level helpers: CRCs, checksums, Manchester, bit-string conversion.

Bit rows are plain Python strings of '0'/'1'. That keeps searching for sync
words trivial (str.find) and is fast enough for the packet sizes involved.

Conventions match the ones used by rtl_433 so protocol documentation from
that project can be applied directly:
  * crc8/crc16 are MSB-first, non-reflected.
  * Manchester: "01" -> 1, "10" -> 0 (the second half-bit is the value).
"""
from __future__ import annotations

from typing import Iterable, Optional


def crc8(data: Iterable[int], poly: int, init: int = 0) -> int:
    rem = init & 0xFF
    for byte in data:
        rem ^= byte
        for _ in range(8):
            rem = ((rem << 1) ^ poly) & 0xFF if rem & 0x80 else (rem << 1) & 0xFF
    return rem


def crc16(data: Iterable[int], poly: int, init: int = 0) -> int:
    rem = init & 0xFFFF
    for byte in data:
        rem ^= byte << 8
        for _ in range(8):
            rem = ((rem << 1) ^ poly) & 0xFFFF if rem & 0x8000 else (rem << 1) & 0xFFFF
    return rem


def lfsr_digest8_reflect(data: bytes, gen: int, key: int) -> int:
    """LFSR-based 8-bit digest, processing bytes last-to-first, bits LSB-first."""
    total = 0
    for byte in reversed(data):
        for i in range(8):
            if (byte >> i) & 1:
                total ^= key
            key = ((key << 1) ^ gen) & 0xFF if key & 0x80 else (key << 1) & 0xFF
    return total


def add_bytes(data: Iterable[int]) -> int:
    return sum(data) & 0xFF


def parity8(byte: int) -> int:
    return bin(byte & 0xFF).count("1") & 1


def parity_bytes(data: Iterable[int]) -> int:
    p = 0
    for b in data:
        p ^= parity8(b)
    return p


def bytes_to_bits(data: bytes) -> str:
    return "".join(f"{b:08b}" for b in data)


def bits_to_bytes(bits: str, offset: int = 0, nbytes: Optional[int] = None) -> bytes:
    """Pack a '0'/'1' string into bytes, MSB first. Trailing partial byte is dropped."""
    usable = (len(bits) - offset) // 8
    if nbytes is not None:
        usable = min(usable, nbytes)
    return bytes(int(bits[offset + 8 * i: offset + 8 * i + 8], 2) for i in range(max(usable, 0)))


def hex_to_bits(hexstr: str) -> str:
    return "".join(f"{int(c, 16):04b}" for c in hexstr)


def invert(bits: str) -> str:
    return bits.translate(str.maketrans("01", "10"))


def manchester_decode(bits: str, start: int = 0, max_bits: int = 0) -> str:
    """Decode until the first invalid symbol ("00" or "11") or max_bits."""
    out = []
    i = start
    while i + 1 < len(bits):
        a, b = bits[i], bits[i + 1]
        if a == b:
            break
        out.append(b)
        i += 2
        if max_bits and len(out) >= max_bits:
            break
    return "".join(out)


def bcd(byte: int) -> int:
    return (byte >> 4) * 10 + (byte & 0x0F)


def is_bcd(byte: int) -> bool:
    return (byte >> 4) <= 9 and (byte & 0x0F) <= 9
