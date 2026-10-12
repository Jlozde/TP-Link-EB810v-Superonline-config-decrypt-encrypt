#!/usr/bin/env python3
"""TP-Link EB810v - Eski Versiyon (DES-ECB) Konfigurasyon Acma / Desifre Araci.

Eski bellenim surumlerinde (CVE-2025-30239 oncesi) alinan Web UI yedek dosyalarini
(conf.bin) ProductID tabanli DES-ECB ile cozer ve XML olarak kaydeder.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
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
MAX_XML_SIZE = 4 * 1024 * 1024


def parse_product_id(value: str) -> int:
    value = value.strip().lower()
    if value.startswith("0x"):
        return int(value, 16)
    return int(value, 10)


def derive_key(product_id: int) -> bytes:
    product_hex = f"{product_id:08x}".encode("ascii")
    return bytes(base ^ char for base, char in zip(BASE_KEY, product_hex))


def decrypt_old_backup(source: bytes, product_id: int = DEFAULT_PRODUCT_ID) -> bytes:
    if not source or len(source) % DES.block_size != 0:
        raise ValueError("Girdi dosyasi boyutu 8 baytin kati degil!")

    key = derive_key(product_id)
    decrypted = DES.new(key, DES.MODE_ECB).decrypt(source)

    padding = None
    for count in range(DES.block_size):
        body = decrypted[16 : len(decrypted) - count]
        if decrypted[:16] == hashlib.md5(body).digest():
            padding = count
            break

    if padding is None:
        raise ValueError("MD5 dogrulamasi basarisiz! Product ID yanlis veya dosya formati uyumsuz.")

    payload = decrypted[16 : len(decrypted) - padding]
    if len(payload) < 5:
        raise ValueError("Desifre edilen veri cok kisa!")

    xml_size = struct.unpack_from("<I", payload, 0)[0]
    if not 1 <= xml_size <= MAX_XML_SIZE:
        raise ValueError(f"Gecersiz XML boyutu: {xml_size}")

    tpconf_bin_xml.packint = "<I"
    xml = bytes(tpconf_bin_xml.uncompress(payload)).rstrip(b"\x00")
    if not xml.startswith(b"<?xml"):
        raise ValueError("Acilan veri gecerli bir XML belgesi ile baslamiyor!")

    return xml


def main() -> int:
    parser = argparse.ArgumentParser(
        description="TP-Link EB810v Eski Versiyon (DES) Yedek Acma Araci"
    )
    parser.add_argument("input", type=Path, help="Sifreli yedek dosyasi (orn: conf.bin)")
    parser.add_argument("output", type=Path, help="Cikti XML dosya yolu (orn: config.xml)")
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

    source = args.input.read_bytes()
    xml = decrypt_old_backup(source, args.product_id)
    args.output.write_bytes(xml)

    print("[+] Basarili: Eski DES yedegi cozuldu.")
    print(f"    Girdi boyutu : {len(source)} bayt")
    print(f"    XML boyutu   : {len(xml)} bayt")
    print(f"    Kayit yeri   : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
