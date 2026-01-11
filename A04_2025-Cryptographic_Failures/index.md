### A04:2025 - Kriptografik Hatalar
Bu zafiyet, hassas verilerin (parolalar, kredi kartları, kişisel veriler) yetersiz şifreleme veya yanlış anahtar yönetimi nedeniyle saldırganlar tarafından okunabilir hale gelmesidir.

### Temel Risk Belirtileri:

**Zayıf Algoritmalar:** 
MD5, SHA1, DES veya RC4 gibi artık güvenli kabul edilmeyen (kırılmış) algoritmaların kullanımı.

**Düz Metin İletişimi:** 
Verilerin HTTP, FTP veya SMTP gibi şifrelenmemiş kanallar üzerinden taşınması.

**Sabit Kodlanmış Anahtarlar** 
Şifreleme anahtarlarının kodun içine (hardcoded) yazılması.

**Yetersiz Rastgele Değerler:** 
Tahmin edilebilir rastgele sayı üreteçleri kullanmak.

**Eski Protokoller**
TLS 1.0 veya 1.1 gibi güvensiz aktarım protokollerinin kullanımı.


### Java Uygulamalarında Önlemler ve Kod Örnekleri

**1. Parola Saklama (Hashing)**
Parolalar asla şifrelenmez (encryption), her zaman hash'lenir. MD5 veya SHA-256 yerine, "salt" (tuzlama) ve "work factor" (iş yükü) desteği olan algoritmalar kullanılmalıdır.

Yanlış: MessageDigest.getInstance("MD5") Doğru (Spring Security - BCrypt):

```java

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class PasswordService {
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12); // Work factor: 12

    public String hashPassword(String rawPassword) {
        // Otomatik olarak her şifre için farklı bir 'salt' oluşturur
        return encoder.encode(rawPassword);
    }

    public boolean verifyPassword(String rawPassword, String encodedPassword) {
        return encoder.matches(rawPassword, encodedPassword);
    }
}

```

**2. Güvenli Simetrik Şifreleme (AES-GCM)**

Veri saklarken (Data at Rest) AES kullanılmalıdır. Ancak AES'in ECB modu güvensizdir (aynı bloklar aynı şifreyi üretir). Modern ve güvenli olan GCM (Galois/Counter Mode) tercih edilmelidir.

```java

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;

public class EncryptionUtil {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12; // GCM için standart 12 byte IV

    public byte[] encrypt(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        byte[] iv = new byte[IV_LENGTH_BYTE];
        new SecureRandom().nextBytes(iv); // Rastgele IV oluşturma

        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        byte[] cipherText = cipher.doFinal(data);
        
        // IV'yi ve şifreli metni birleştirip döndürün (IV gizli değildir ama gereklidir)
        byte[] combined = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(cipherText, 0, combined, iv.length, cipherText.length);
        return combined;
    }
}

```

**3. Güvenli Rastgele Sayı Üretimi**

Önemli anahtarlar, tokenlar veya "salt" değerleri üretilirken java.util.Random asla kullanılmamalıdır. Bunun yerine kriptografik olarak güvenli olan SecureRandom kullanılmalıdır.

```java

import java.security.SecureRandom;
import java.util.Base64;

public class TokenGenerator {
    public String generateSafeToken() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}

```

**4. Veri İletişim Güvenliği (TLS)**

Java istemcilerinde (HttpClient) eski protokolleri devre dışı bırakıp **TLS 1.2** veya **1.3** zorunlu kılınmalıdır.

```java
// JVM seviyesinde sadece güvenli protokolleri zorunlu kılmak için:
System.setProperty("https.protocols", "TLSv1.2,TLSv1.3");

```


