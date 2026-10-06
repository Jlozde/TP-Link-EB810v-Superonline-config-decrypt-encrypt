#!/usr/bin/env python3
"""TP-Link EB810v Configuration All-in-One CLI Tool
Birleşik yönetim aracı: decrypt, encrypt, verify ve info komutlarını içerir.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

import tpconf_core


def cmd_decrypt(args: argparse.Namespace) -> int:
    in_path = Path(args.input)
    out_path = Path(args.output)
    if not in_path.is_file():
        print(f"HATA: Girdi dosyası bulunamadı: {in_path}")
        return 1
    if out_path.exists() and not args.force:
        print(f"HATA: Çıkış dosyası zaten var: {out_path} (-f ile zorlayın)")
        return 1

    key = tpconf_core.EB810V_BACKUP_KEY
    if args.key:
        key = bytes.fromhex(args.key) if not args.key in tpconf_core.KNOWN_KEYS else tpconf_core.KNOWN_KEYS[args.key]

    print(f"[*] Çözülüyor: {in_path} -> {out_path}")
    raw_bin = in_path.read_bytes()
    xml = tpconf_core.decrypt_config(raw_bin, key=key, little_endian=not args.big_endian)
    out_path.write_bytes(xml)
    print(f"[+] Tamamlandı! ({len(xml):,} bayt)")
    return 0


def cmd_encrypt(args: argparse.Namespace) -> int:
    in_path = Path(args.input)
    out_path = Path(args.output)
    if not in_path.is_file():
        print(f"HATA: Girdi dosyası bulunamadı: {in_path}")
        return 1
    if out_path.exists() and not args.force:
        print(f"HATA: Çıkış dosyası zaten var: {out_path} (-f ile zorlayın)")
        return 1

    key = tpconf_core.EB810V_BACKUP_KEY
    if args.key:
        key = bytes.fromhex(args.key) if not args.key in tpconf_core.KNOWN_KEYS else tpconf_core.KNOWN_KEYS[args.key]

    print(f"[*] Şifreleniyor: {in_path} -> {out_path}")
    raw_xml = in_path.read_bytes()
    bin_data = tpconf_core.encrypt_config(raw_xml, key=key, little_endian=not args.big_endian, skiphits=args.skiphits)
    out_path.write_bytes(bin_data)
    print(f"[+] Tamamlandı! ({len(bin_data):,} bayt)")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.is_file():
        print(f"HATA: Dosya bulunamadı: {path}")
        return 1

    data = path.read_bytes()
    print(f"Dosya: {path}")
    print(f"Boyut: {len(data):,} bayt")
    print(f"SHA256: {hashlib.sha256(data).hexdigest()}")

    if data.strip().startswith(b"<?xml") or data.strip().startswith(b"<"):
        print("Biçim: Açık Düz Metin XML")
        return 0

    print("Biçim: Şifreli / İkili Dosya (Test ediliyor...)")
    for name, k in tpconf_core.KNOWN_KEYS.items():
        try:
            xml = tpconf_core.decrypt_config(data, key=k)
            print(f"[+] Doğrulandı! Anahtar '{name}' ({k.hex()}) ile başarıyla çözüldü.")
            print(f"    Açılan XML boyutu: {len(xml):,} bayt")
            return 0
        except Exception:
            pass

    print("[-] Bilinen anahtarlarla doğrulanamadı.")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="TP-Link EB810v Konfigürasyon Aracı")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # decrypt
    p_dec = subparsers.add_parser("decrypt", help="Şifreli .bin dosyasını XML'e çevir")
    p_dec.add_argument("input", help="Girdi .bin dosyası")
    p_dec.add_argument("output", help="Çıkış .xml dosyası")
    p_dec.add_argument("-k", "--key", help="Özel DES anahtarı")
    p_dec.add_argument("-f", "--force", action="store_true", help="Var olan dosyanın üzerine yaz")
    p_dec.add_argument("-b", "--big-endian", action="store_true", help="Big endian modu")
    p_dec.set_defaults(func=cmd_decrypt)

    # encrypt
    p_enc = subparsers.add_parser("encrypt", help="XML dosyasını şifreli .bin'e çevir")
    p_enc.add_argument("input", help="Girdi .xml dosyası")
    p_enc.add_argument("output", help="Çıkış .bin dosyası")
    p_enc.add_argument("-k", "--key", help="Özel DES anahtarı")
    p_enc.add_argument("-f", "--force", action="store_true", help="Var olan dosyanın üzerine yaz")
    p_enc.add_argument("-b", "--big-endian", action="store_true", help="Big endian modu")
    p_enc.add_argument("-s", "--skiphits", action="store_true", help="Gevşek sıkıştırma")
    p_enc.set_defaults(func=cmd_encrypt)

    # verify
    p_ver = subparsers.add_parser("verify", help="Dosya bütünlüğünü ve anahtar uyumunu doğrula")
    p_ver.add_argument("file", help="İncelenecek dosya (.bin veya .xml)")
    p_ver.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
