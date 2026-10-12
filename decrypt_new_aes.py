#!/usr/bin/env python3
"""TP-Link EB810v - Yeni Versiyon (AES-128-CBC) Konfigurasyon Acma / Desifre Araci.

Yeni bellenim surumlerinde (Mart 2026+ / CVE-2025-30239 yamali) alinan Web UI yedek dosyalarini
(conf.bin) Qualcomm TRK tabanli AES-128-CBC ile cozer ve XML olarak kaydeder.
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

# Firmware icerisindeki gKey ve gIv sabitleri
AES_GKEY = b"1528632946736109\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
AES_GIV = b"1528632946736539"

# CPU / Donanim imza tablosu (MPIDR_EL1, MIDR_EL1, CTR_EL0, Cortex-A73 PartNum)
HW_INFO_BUF = struct.pack("<QQQQ", 0x80000000, 0x411FD090, 0x84448004, 0xD09) + b"\x00" * (800 - 32)
MAX_XML_SIZE = 4 * 1024 * 1024


def derive_aes_key(model_name: str = "EB810v") -> bytes:
    h = hmac.new(model_name.encode("ascii"), HW_INFO_BUF, hashlib.sha256).digest()
    return bytes(AES_GKEY[i] ^ h[i] for i in range(16))


def decrypt_new_backup(source: bytes, model_name: str = "EB810v") -> bytes:
    if not source or len(source) % AES.block_size != 0:
        raise ValueError("Girdi dosyasi boyutu 16 baytin (AES blok boyutu) kati degil!")

    key = derive_aes_key(model_name)
    decrypted = AES.new(key, AES.MODE_CBC, AES_GIV).decrypt(source)

    # MD5 dogrulamasi ve PKCS#7 dolgu tespiti
    padding = None
    for count in range(AES.block_size):
        body = decrypted[16 : len(decrypted) - count]
        if decrypted[:16] == hashlib.md5(body).digest():
            padding = count
            break

    if padding is None:
        raise ValueError("MD5 dogrulamasi basarisiz! Model adi yanlis veya dosya AES ile sifrelenmemis.")

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
        description="TP-Link EB810v Yeni Versiyon (AES-128-CBC) Yedek Acma Araci"
    )
    parser.add_argument("input", type=Path, help="Sifreli yeni yedek dosyasi (orn: conf.bin)")
    parser.add_argument("output", type=Path, help="Cikti XML dosya yolu (orn: config.xml)")
    parser.add_argument(
        "--model-name",
        default="EB810v",
        help="Cihaz model adi (Varsayilan: EB810v)",
    )
    parser.add_argument("-f", "--force", action="store_true", help="Varsa ciktinin uzerine yaz")
    args = parser.parse_args()

    if args.output.exists() and not args.force:
        parser.error(f"Cikti dosyasi zaten var, uzerine yazmak icin -f kullanin: {args.output}")

    source = args.input.read_bytes()
    xml = decrypt_new_backup(source, args.model_name)
    args.output.write_bytes(xml)

    print("[+] Basarili: Yeni AES yedegi cozuldu.")
    print(f"    Girdi boyutu : {len(source)} bayt")
    print(f"    XML boyutu   : {len(xml)} bayt")
    print(f"    Kayit yeri   : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
