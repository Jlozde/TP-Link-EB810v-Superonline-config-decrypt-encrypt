# TP-Link EB810v Konfigürasyon Yedekleme & Açma Araçları

Bu klasör, TP-Link EB810v cihazlarının web arayüzünden indirilen yedek (`conf.bin`) dosyalarını çözmek (XML formatına dönüştürmek), düzenlemek ve tekrar cihaza yüklenebilir formatta paketlemek için hazırlanmış 4 adet Python betiğini içerir.

---

> **⚠️ Sorumluluk Reddi**
>
> Bu rehber, yalnızca kendi sorumluluğunuzdaki modemlerde kullanılması için, deneysel amaçla hazırlanmıştır. Yapılan işlemler hakkında yeterli bilgiye sahip değilseniz, donanımınıza veya kendinize zarar verme riski bulunmaktadır. Sahipliğinin internet servis sağlayıcınıza ait oldığu modemlerde uygulanması yasal olmayabilir. Lütfen ne yaptığınızı bilerek ilerleyin veya bu işlemlerden kaçının.


## 📁 Araç Listesi

| Betik Adı | İşlev | Algoritma / Sürüm |
| :--- | :--- | :--- |
| **`decrypt_old_des.py`** | Eski yedekleri açar | DES-ECB (ProductID: `0x5C56E801`) |
| **`encrypt_old_des.py`** | Eski formatta paketler | DES-ECB + LZSS + MD5 |
| **`decrypt_new_aes.py`** | Yeni yedekleri açar | AES-128-CBC (Qualcomm TRK / Mart 2026+) |
| **`encrypt_new_aes.py`** | Yeni formatta paketler | AES-128-CBC + PKCS#7 + LZSS + MD5 |

> **Bağımlılık:** Betikler Python 3 ve `pycryptodome` kütüphanesini kullanır. Gerekirse yüklemek için:
> ```bash
> pip install pycryptodome
> ```

---

## 🚀 Kullanım Örnekleri

### 1. Eski Sürüm Firmware (CVE-2025-30239 Öncesi)

**Yedek Çözme (conf.bin -> config.xml):**
```bash
python decrypt_old_des.py conf.bin config.xml -f
```

**Yeniden Paketleme (config.xml -> conf_mod.bin):**
```bash
python encrypt_old_des.py config.xml conf_mod.bin -f
```

---

### 2. Yeni Sürüm Firmware (Mart 2026+ / Yamalı Sürüm)

**Yedek Çözme (conf.bin -> config.xml):**
```bash
python decrypt_new_aes.py conf.bin config.xml -f
```

**Yeniden Paketleme (config.xml -> conf_mod.bin):**
```bash
python encrypt_new_aes.py config.xml conf_mod.bin -f
```

*(Her iki betikte de `-f` parametresi varsa var olan dosyanın üzerine yazılmasını sağlar).*

---

## 🛠️ XML İçinde sUser ve SSH Aktivasyonu

Yedek dosyasını XML olarak açtıktan sonra, metin düzenleyici ile açıp aşağıdaki blokları ekleyebilir veya güncelleyebilirsiniz:

### 1. `sUser` (Süper Kullanıcı / Admin Yetkisi) Eklenmesi

XML dosyasında `<X_TP_UserCfg>` ve `<Users>` etiketlerini bulun.

#### Adım 1.1: `<X_TP_UserCfg>` Bloğu
Bu blokta `AdminName` değerini `sUser`, parolasını ise belirleyeceğiniz şifre (örneğin `admin`) yapın:

```xml
    <X_TP_UserCfg>
      <UserPwdSign val=1 />
      <AdminName val=sUser />
      <AdminPwd val=admin />
      <AdminPwdBackup val=admin />
      <AdminEnable val=1 />
      <UserName val=admin />
      <UserPwd val=superonline />
      <UserPwdBackup val=superonline />
    </X_TP_UserCfg>
```

#### Adım 1.2: `<Users>` Bloğu
Web ve sistem yetkilendirme listesinde `sUser` hesabı için `instance=2` kaydının tanımlı olduğundan emin olun:

```xml
    <Users>
      <UserNumberOfEntries val=2 />
      <User instance=1 >
        <Enable val=1 />
        <RemoteAccessCapable val=1 />
        <Username val=admin />
        <Password val=superonline />
      </User>
      <User instance=2 >
        <Enable val=1 />
        <RemoteAccessCapable val=1 />
        <Username val=sUser />
        <Password val=admin />
      </User>
    </Users>
```

---

### 2. SSH (Dropbear) ve Telnet Servislerinin Aktif Edilmesi

XML dosyasında `<X_TP_AppCfg>` etiketinin içine `<SSHCfg>` bloğunu ekleyin veya mevcutsa değerlerini `1` yapın:

```xml
    <X_TP_AppCfg>
      <SSHCfg>
        <LocalEnabled val=1 />
        <LocalPort val=22 />
        <RemoteEnabled val=0 />
        <RemotePort val=22 />
        <RemoteAll val=0 />
        <SessionLifeTime val=0 />
        <HideInEasyMenu val=0 />
      </SSHCfg>
      <HttpCfg>
        <TelnetLocalEnabled val=1 />
        <TelnetLocalPort val=2323 />
        ...
      </HttpCfg>
    </X_TP_AppCfg>
```

* **`LocalEnabled val=1`**: Yerel ağdan (LAN) Port 22 SSH bağlantılarını kabul eder.
* **`LocalPort val=22`**: SSH servis portu (Dropbear).
* **`TelnetLocalEnabled val=1`**: Yerel ağdan Port 2323 Telnet erişimini açar.

---

## 📥 Cihaza Geri Yükleme Adımları

1. Düzenlediğiniz `config.xml` dosyasını modeminizin firmware sürümüne göre ilgili encrypt betiğiyle paketleyin:
   ```bash
   python encrypt_new_aes.py config.xml conf_mod.bin -f
                   ^
                   veya old
   ```
2. Modemin web arayüzüne girin (`http://192.168.1.1` veya `http://192.168.55.1`).
3. **Yönetim / Bakım (Management) -> Yedekleme ve Geri Yükleme (Backup & Restore)** sayfasına gidin.
4. Üretilen `conf_mod.bin` dosyasını seçip **Geri Yükle (Restore)** butonuna tıklayın.
5. Cihaz yeniden başladıktan sonra yeni ayarlarınız aktif olacaktır.
