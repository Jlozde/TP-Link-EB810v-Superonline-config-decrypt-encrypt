# TP-Link EB810v Konfigürasyon Çözücü ve Şifreleyici (Mod Araçları)

Bu dizin, TP-Link EB810v (ve benzeri TP-Link modelleri) için yedek dosyalarını (`conf.bin`) çözmek, XML olarak düzenlemek ve tekrar modeme yüklenebilir şifreli `.bin` dosyası haline getirmek için hazırlanmış bağımsız Python araçlarını içerir.

---

> **⚠️ Sorumluluk Reddi**
>
> Bu rehber, yalnızca kendi sorumluluğunuzdaki modemlerde kullanılması için, deneysel amaçla hazırlanmıştır. Yapılan işlemler hakkında yeterli bilgiye sahip değilseniz, donanımınıza veya kendinize zarar verme riski bulunmaktadır. Sahipliğinin internet servis sağlayıcınıza ait oldığu modemlerde uygulanması yasal olmayabilir. Lütfen ne yaptığınızı bilerek ilerleyin veya bu işlemlerden kaçının.


## 📁 Dosyalar

| Dosya | Açıklama |
|---|---|
| [`decrypt.py`](decrypt.py) | Şifrelenmiş `.bin` yedek dosyasını açık `.xml` metnine çözer. |
| [`encrypt.py`](encrypt.py) | Düzenlenmiş `.xml` dosyasını şifreli `.bin` dosyasına dönüştürür. |
| [`tpconf_tool.py`](tpconf_tool.py) | Hepsi bir arada komut satırı aracı (`decrypt`, `encrypt`, `verify`). |
| [`tpconf_core.py`](tpconf_core.py) | DES-ECB, MD5, LZSS sıkıştırma/açma motoru. |

---

## 🚀 Hızlı Kullanım

### 1. Şifreli Yedeği XML'e Çözme (`decrypt.py`)

Hiçbir parametre vermeden çalıştırırsanız, klasördeki veya üst klasördeki `EB810v_backup_conf.bin` dosyasını otomatik olarak bulur ve çözer:

```powershell
python decrypt.py
```

Veya özel dosya isimleri belirterek:

```powershell
python decrypt.py EB810v_backup_conf.bin cozulmus_ayar.xml
```

Varsayılan üzerine yazmak için:
```powershell
python decrypt.py -f EB810v_backup_conf.bin cozulmus_ayar.xml
```

---

### 2. XML Dosyasını Şifreleyip Paketleme (`encrypt.py`)

Düzenlediğiniz XML dosyasını modeme yüklenebilecek `conf.bin` formatına getirmek için:

```powershell
python encrypt.py cozulmus_ayar.xml EB810v_yeni_yedek.bin
```

Otomatik mod (üst dizindeki `EB810v_backup_conf.xml` dosyasını bulur):
```powershell
python encrypt.py
```

---

### 3. Hepsi Bir Arada Araç (`tpconf_tool.py`)

```powershell
# Çözme
python tpconf_tool.py decrypt EB810v_backup_conf.bin cozulmus.xml

# Şifreleme
python tpconf_tool.py encrypt cozulmus.xml yeni_yedek.bin

# Dosya doğrulama ve anahtar testi
python tpconf_tool.py verify EB810v_backup_conf.bin
```

---

## 🔑 EB810v Kriptografik Parametreleri

- **Algoritma:** DES-ECB
- **Canlı Cihaz Anahtarı:** `41 ee 90 3d 9c 06 1d fe`
- **Türetme Yöntemi:** `libcmm.so` içindeki `getBackNRestoreK` algoritması:
  - `[0x74, 0x8d, 0xa5, 0x0b, 0xf9, 0x3e, 0x2d, 0xcf]` XOR `"%08x"` (`X_TP_ProductID` = `1549199361` -> `"5c56e801"`)
- **İç Bellenim Anahtarı:** `47 8d a5 0f f9 e3 d2 cb` (`default_config.xml` ve `reduced_data_model.xml` için)
- **Doğrulama:** İlk 16 bayt, sıkıştırılmış gövdenin MD5 özetidir.
- **Sıkıştırma:** TP-Link tescilli LZSS algoritması (Little-Endian).
