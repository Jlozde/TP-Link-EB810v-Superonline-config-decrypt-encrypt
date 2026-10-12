#!/usr/bin/env python3
"""TP-Link EB810v - Eski Versiyon (DES-ECB) Konfigurasyon Paketleme / Sifreleme Araci.

Duzenlenmis XML konfigurasyon dosyasini sikistirir, MD5 basligi ekler,
ve eski bellenimlerin kabul edecegi sekilde ProductID tabanli DES-ECB ile sifreler.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

try:
    from Cryptodome.Cipher import DES
except ImportError:
    from Crypto.Cipher import DES

import tpconf_bin_xml

BASE_KEY = bytes.fromhex("748da50bf93e2dcf")
DEFAULT_PRODUCT_ID = 1549199361  # 0x5C56E801


def parse_product_id(value: str) -> int:
    value = value.strip().lower()
    if value.startswith("0x"):
        return int(value, 16)
    return int(value, 10)


def derive_key(product_id: int) -> bytes:
    product_hex = f"{product_id:08x}".encode("ascii")
    return bytes(base ^ char for base, char in zip(BASE_KEY, product_hex))


def encrypt_old_backup(xml: bytes, product_id: int = DEFAULT_PRODUCT_ID) -> bytes:
    tpconf_bin_xml.packint = "<I"
    if not xml.endswith(b"\x00"):
        xml = xml + b"\x00"

    size, compressed = tpconf_bin_xml.compress(xml, False)
    compressed_bytes = bytes(compressed)
    md5_digest = hashlib.md5(compressed_bytes).digest()
    raw_pt = md5_digest + compressed_bytes

    # 8 bayt blok sinirina sifir dolgusu (zero-padding)
    pad_len = (8 - (len(raw_pt) % 8)) % 8
    padded_pt = raw_pt + b"\x00" * pad_len

    key = derive_key(product_id)
    return DES.new(key, DES.MODE_ECB).encrypt(padded_pt)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="TP-Link EB810v Eski Versiyon (DES) Yedek Paketleme Araci"
    )
    parser.add_argument("input", type=Path, help="Duzenlenmis kaynak XML dosyasi")
    parser.add_argument("output", type=Path, help="Uretilecek sifreli yedek dosyasi (orn: conf.bin)")
    parser.add_argument(
        "--product-id",
        default=DEFAULT_PRODUCT_ID,
        type=parse_product_id,
        help=f"X_TP_ProductID (Varsayilan: 0x{DEFAULT_PRODUCT_ID:08X})",
    )
    parser.add_argument("-f", "--force", action="store_true", help="Varsa ciktinin uzerine yaz")
    args = parser.parse_args()

    if args.output.exists() and not args.force:
        parser.error(f"Cikti dosyasi zaten var, uzerine yazmak icin -f kullanin: {args.output}")

    xml = args.input.read_bytes()
    if not xml.startswith(b"<?xml"):
        print("[-] UYARI: Girdi verisi '<?xml' ile baslamiyor!")

    ciphertext = encrypt_old_backup(xml, args.product_id)
    args.output.write_bytes(ciphertext)

    print("[+] Basarili: Eski DES yedei paketlendi.")
    print(f"    Kaynak XML   : {len(xml)} bayt")
    print(f"    Sifreli BIN  : {len(ciphertext)} bayt")
    print(f"    Kayit yeri   : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
