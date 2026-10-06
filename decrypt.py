#!/usr/bin/env python3
"""TP-Link EB810v Configuration Backup Decryptor
Kullanım:
  python decrypt.py [girdi.bin] [cikti.xml]
Örnekler:
  python decrypt.py
  python decrypt.py EB810v_backup_conf.bin cozulmus_ayar.xml
  python decrypt.py --key 478da50ff9e3d2cb default_config.xml default_config.xml
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

# Yerel modül yolunu ekle
CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

import tpconf_core


def find_default_input() -> Path | None:
    candidates = [
        CURRENT_DIR / "conf.bin",
        CURRENT_DIR / "EB810v_backup_conf.bin",
        CURRENT_DIR.parent / "EB810v_backup_conf.bin",
        CURRENT_DIR.parent / "conf.bin",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def parse_key(key_arg: str | None, product_id_arg: str | None) -> bytes:
    if product_id_arg:
        val = int(product_id_arg, 16 if product_id_arg.lower().startswith("0x") else 10)
        return tpconf_core.derive_key_from_product_id(val)
    if not key_arg:
        return tpconf_core.EB810V_BACKUP_KEY

    key_arg_lower = key_arg.lower().strip()
    if key_arg_lower in tpconf_core.KNOWN_KEYS:
        return tpconf_core.KNOWN_KEYS[key_arg_lower]

    try:
        clean_hex = key_arg.replace(" ", "").replace(":", "")
        parsed = bytes.fromhex(clean_hex)
        if len(parsed) != 8:
            raise ValueError
        return parsed
    except Exception:
        print(f"HATA: Geçersiz 8 baytlık DES anahtarı: {key_arg}")
        sys.exit(1)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="TP-Link EB810v şifrelenmiş conf.bin yedeğini XML formatına çözer (Decrypt & Decompress)."
    )
    parser.add_argument(
        "input",
        nargs="?",
        type=Path,
        help="Şifreli .bin dosyası (Varsayılan: bulunan ilk conf.bin veya EB810v_backup_conf.bin)",
    )
    parser.add_argument(
        "output",
        nargs="?",
        type=Path,
        help="Çözülmüş XML çıkış dosyası (Varsayılan: girdi_adi.xml)",
    )
    parser.add_argument(
        "-k",
        "--key",
        help="Özel DES anahtarı (hex formatında veya 'eb810v', 'firmware_default')",
    )
    parser.add_argument(
        "-p",
        "--product-id",
        help="X_TP_ProductID değeri (örn: 1549199361 veya 0x5c56e001)",
    )
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Var olan çıkış dosyasının üzerine yaz",
    )
    parser.add_argument(
        "-b",
        "--big-endian",
        action="store_true",
        help="Big-endian bayt sırası kullan (EB810v little-endian kullanır)",
    )

    args = parser.parse_args()

    input_path = args.input
    if not input_path:
        default_in = find_default_input()
        if not default_in:
            print("HATA: Girdi dosyası belirtilmedi ve çalışma dizininde conf.bin bulunamadı.")
            parser.print_help()
            return 1
        input_path = default_in
        print(f"[*] Otomatik girdi dosyası seçildi: {input_path}")

    if not input_path.is_file():
        print(f"HATA: Belirtilen girdi dosyası bulunamadı: {input_path}")
        return 1

    output_path = args.output
    if not output_path:
        stem = input_path.stem
        if stem.endswith(".bin"):
            stem = stem[:-4]
        output_path = input_path.with_name(f"{stem}.xml")
        print(f"[*] Otomatik çıkış dosyası belirlendi: {output_path}")

    if output_path.exists() and not args.force:
        print(f"UYARI: Çıkış dosyası zaten var: {output_path}")
        print("Üzerine yazmak için -f veya --force parametresini kullanın.")
        return 1

    des_key = parse_key(args.key, args.product_id)
    little_endian = not args.big_endian

    print(f"[*] Girdi: {input_path} ({input_path.stat().st_size:,} bayt)")
    print(f"[*] DES Anahtarı: {des_key.hex()}")

    bin_data = input_path.read_bytes()
    try:
        xml_data = tpconf_core.decrypt_config(
            bin_data, key=des_key, little_endian=little_endian
        )
    except Exception as exc:
        print(f"[-] ÇÖZME HATASI: {exc}")
        return 1

    output_path.write_bytes(xml_data)

    in_hash = hashlib.sha256(bin_data).hexdigest()
    out_hash = hashlib.sha256(xml_data).hexdigest()

    print("[+] BAŞARILI!")
    print(f"    Çözülen XML: {output_path}")
    print(f"    Boyut: {len(xml_data):,} bayt")
    print(f"    Girdi SHA256 : {in_hash}")
    print(f"    Çıktı SHA256 : {out_hash}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
