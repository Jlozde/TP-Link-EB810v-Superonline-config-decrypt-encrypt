#!/usr/bin/env python3
"""TP-Link EB810v Configuration Cryptographic & Compression Engine
Supports:
  - DES-ECB encryption / decryption
  - MD5 integrity check
  - TP-Link custom LZSS compression / decompression
  - Key derivation from X_TP_ProductID
"""

import sys
from pathlib import Path
from hashlib import md5
from struct import pack_into, unpack_from

# Auto-add parent .tools directory if present
_tools_dir = Path(__file__).resolve().parent.parent / ".tools"
if _tools_dir.is_dir():
    sys.path.insert(0, str(_tools_dir))

try:
    from Cryptodome.Cipher import DES
except ImportError:
    try:
        from Crypto.Cipher import DES
    except ImportError as exc:
        raise ImportError(
            "pycryptodome or pycryptodomex is required. Install via: pip install pycryptodomex"
        ) from exc


# EB810v specific keys
EB810V_BACKUP_KEY = bytes.fromhex("41ee903d9c061dfe")
FIRMWARE_DEFAULT_KEY = bytes.fromhex("478da50ff9e3d2cb")
BASE_KEY = bytes.fromhex("748da50bf93e2dcf")

KNOWN_KEYS = {
    "eb810v": EB810V_BACKUP_KEY,
    "firmware_default": FIRMWARE_DEFAULT_KEY,
    "tplink_default": bytes.fromhex("478da50bf9e3d2cf"),
    "ex530v": bytes.fromhex("40bac66cca5a1cfe"),
    "ex230v": bytes.fromhex("40b49333c90b1dfe"),
    "vc220": bytes.fromhex("40ecc43aca0a1dfe"),
}

MAX_XML_SIZE = 4 * 1024 * 1024  # 4 MB


def derive_key_from_product_id(product_id: int) -> bytes:
    """Derive DES key using TP-Link libcmm getBackNRestoreK algorithm."""
    product_hex = f"{product_id:08x}".encode("ascii")
    return bytes(b ^ c for b, c in zip(BASE_KEY, product_hex))


def uncompress(src: bytes, little_endian: bool = True) -> bytes:
    """Decompress TP-Link custom LZSS compressed buffer."""
    packint = "<I" if little_endian else ">I"
    size = unpack_from(packint, src, 0)[0]
    if size > MAX_XML_SIZE or size <= 0:
        raise ValueError(f"Invalid decompressed size header: {size}")

    dst = bytearray(size)
    block16_countdown = 0
    block16_dict_bits = 0
    s_p = 4
    d_p = 0

    def get_bit():
        nonlocal block16_countdown, block16_dict_bits, s_p
        if block16_countdown:
            block16_countdown -= 1
        else:
            block16_dict_bits = unpack_from("<H" if little_endian else ">H", src, s_p)[0]
            s_p += 2
            block16_countdown = 0xF
        block16_dict_bits = block16_dict_bits << 1
        return 1 if block16_dict_bits & 0x10000 else 0

    def get_dict_ld():
        bits = 1
        while True:
            bits = (bits << 1) + get_bit()
            if not get_bit():
                break
        return bits

    dst[d_p] = src[s_p]
    s_p += 1
    d_p += 1

    while d_p < size:
        if get_bit():
            num_chars = get_dict_ld() + 2
            msb = (get_dict_ld() - 2) << 8
            lsb = src[s_p]
            s_p += 1
            offset = d_p - (lsb + 1 + msb)
            for _ in range(num_chars):
                dst[d_p] = dst[offset]
                d_p += 1
                offset += 1
        else:
            dst[d_p] = src[s_p]
            s_p += 1
            d_p += 1

    return bytes(dst)


def compress(src: bytes, skiphits: bool = False, little_endian: bool = True) -> bytes:
    """Compress buffer using TP-Link custom LZSS algorithm."""
    # Ensure trailing null byte
    if not src.endswith(b"\0"):
        src = src + b"\0"

    size = len(src)
    buffer_countdown = size
    hash_table = [0] * 0x2000
    dst = bytearray(0x80000)  # 512 KB working buffer
    block16_countdown = 0x10
    block16_dict_bits = 0
    d_pb = 5
    d_p = 7
    s_p = 1
    s_ph = 0

    packint = "<I" if little_endian else ">I"
    packshort = "<H" if little_endian else ">H"

    def put_bit(bit):
        nonlocal block16_countdown, block16_dict_bits, d_p, d_pb
        if block16_countdown:
            block16_countdown -= 1
        else:
            pack_into(packshort, dst, d_pb, block16_dict_bits)
            d_pb = d_p
            d_p += 2
            block16_countdown = 0xF
        block16_dict_bits = (bit + (block16_dict_bits << 1)) & 0xFFFF

    def put_dict_ld(bits):
        ldb = bits >> 1
        while True:
            lb = (ldb - 1) & ldb
            if not lb:
                break
            ldb = lb
        put_bit(int(ldb & bits > 0))
        ldb = ldb >> 1
        while ldb:
            put_bit(1)
            put_bit(int(ldb & bits > 0))
            ldb = ldb >> 1
        put_bit(0)

    def hash_key(offset):
        b4 = src[offset : offset + 4]
        hk = 0
        for b in b4[:3]:
            hk = (hk + b) * 0x13D
        return (hk + b4[3]) & 0x1FFF

    pack_into(packint, dst, 0, size)
    dst[4] = src[0]
    buffer_countdown -= 1

    while buffer_countdown > 4:
        while s_ph < s_p:
            hash_table[hash_key(s_ph)] = s_ph
            s_ph += 1
        hit = hash_table[hash_key(s_p)]
        count = 0
        if hit:
            while True:
                if src[hit + count] != src[s_p + count]:
                    break
                count += 1
                if count == buffer_countdown:
                    break
            if count >= 4 or count == buffer_countdown:
                hit_offset = s_p - hit - 1
                put_bit(1)
                put_dict_ld(count - 2)
                put_dict_ld((hit_offset >> 8) + 2)
                dst[d_p] = hit_offset & 0xFF
                d_p += 1
                buffer_countdown -= count
                s_p += count
                if skiphits:
                    hash_table[hash_key(s_ph)] = s_ph
                    s_ph += count
                continue
        put_bit(0)
        dst[d_p] = src[s_p]
        s_p += 1
        d_p += 1
        buffer_countdown -= 1

    while buffer_countdown:
        put_bit(0)
        dst[d_p] = src[s_p]
        s_p += 1
        d_p += 1
        buffer_countdown -= 1

    pack_into(packshort, dst, d_pb, (block16_dict_bits << block16_countdown) & 0xFFFF)
    return bytes(dst[:d_p])


def decrypt_config(bin_data: bytes, key: bytes = EB810V_BACKUP_KEY, little_endian: bool = True) -> bytes:
    """Decrypt and uncompress TP-Link backup config file."""
    if len(bin_data) % 8 != 0:
        raise ValueError("Encrypted config size must be a multiple of 8 bytes.")

    cipher = DES.new(key, DES.MODE_ECB)
    decrypted = cipher.decrypt(bin_data)

    # Check MD5 over varying padding lengths (0 to 7 bytes)
    expected_md5 = decrypted[:16]
    valid_payload = None

    for pad in range(8):
        candidate = decrypted[16 : len(decrypted) - pad]
        if md5(candidate).digest() == expected_md5:
            valid_payload = candidate
            break

    if valid_payload is None:
        raise ValueError("MD5 verification failed. Incorrect DES key or corrupted file.")

    return uncompress(valid_payload, little_endian=little_endian)


def encrypt_config(xml_data: bytes, key: bytes = EB810V_BACKUP_KEY, little_endian: bool = True, skiphits: bool = False) -> bytes:
    """Compress, MD5 hash, pad and encrypt XML config into TP-Link conf.bin format."""
    compressed = compress(xml_data, skiphits=skiphits, little_endian=little_endian)
    digest = md5(compressed).digest()
    payload = digest + compressed

    # Pad to 8-byte boundary
    remainder = len(payload) % 8
    if remainder:
        payload += b"\x00" * (8 - remainder)

    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(payload)
