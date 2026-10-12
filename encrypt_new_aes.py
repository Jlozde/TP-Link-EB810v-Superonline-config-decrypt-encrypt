#!/usr/bin/env python3
"""TP-Link EB810v - Yeni Versiyon (AES-128-CBC) Konfigurasyon Paketleme / Sifreleme Araci.

Duzenlenmis XML konfigurasyon dosyasini sikistirir, MD5 basligi ve PKCS#7 dolgusu ekler,
ve yeni bellenimlerin kabul edecegi sekilde Qualcomm TRK AES-128-CBC ile sifreler.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import struct
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

try:
    from Cryptodome.Cipher import AES
except ImportError:
    from Crypto.Cipher import AES

import tpconf_bin_xml

AES_GKEY = b"1528632946736109\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
AES_GIV = b"1528632946736539"
HW_INFO_BUF = struct.pack("<QQQQ", 0x80000000, 0x411FD090, 0x84448004, 0xD09) + b"\x00" * (800 - 32)


def derive_aes_key(model_name: str = "EB810v") -> bytes:
    h = hmac.new(model_name.encode("ascii"), HW_INFO_BUF, hashlib.sha256).digest()
    return bytes(AES_GKEY[i] ^ h[i] for i in range(16))


def encrypt_new_backup(xml: bytes, model_name: str = "EB810v") -> bytes:
    tpconf_bin_xml.packint = "<I"
    if not xml.endswith(b"\x00"):
        xml = xml + b"\x00"

    size, compressed = tpconf_bin_xml.compress(xml, False)
    compressed_bytes = bytes(compressed)
    md5_digest = hashlib.md5(compressed_bytes).digest()
    raw_pt = md5_digest + compressed_bytes

    # PKCS#7 standart dolgusu (16 bayt blok sinirina)
    pad_len = 16 - (len(raw_pt) % 16)
    if pad_len == 0:
        pad_len = 16
    padded_pt = raw_pt + bytes([pad_len] * pad_len)

    key = derive_aes_key(model_name)
    return AES.new(key, AES.MODE_CBC, AES_GIV).encrypt(padded_pt)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="TP-Link EB810v Yeni Versiyon (AES-128-CBC) Yedek Paketleme Araci"
    )
    parser.add_argument("input", type=Path, help="Duzenlenmis kaynak XML dosyasi")
    parser.add_argument("output", type=Path, help="Uretilecek sifreli yedek dosyasi (orn: conf.bin)")
    parser.add_argument(
        "--model-name",
        default="EB810v",
        help="Cihaz model adi (Varsayilan: EB810v)",
    )
    parser.add_argument("-f", "--force", action="store_true", help="Varsa ciktinin uzerine yaz")
    args = parser.parse_args()

    if args.output.exists() and not args.force:
        parser.error(f"Cikti dosyasi zaten var, uzerine yazmak icin -f kullanin: {args.output}")

    xml = args.input.read_bytes()
    if not xml.startswith(b"<?xml"):
        print("[-] UYARI: Girdi verisi '<?xml' ile baslamiyor!")

    ciphertext = encrypt_new_backup(xml, args.model_name)
    args.output.write_bytes(ciphertext)

    print("[+] Basarili: Yeni AES yedegi paketlendi.")
    print(f"    Kaynak XML   : {len(xml)} bayt")
    print(f"    Sifreli BIN  : {len(ciphertext)} bayt")
    print(f"    Kayit yeri   : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
