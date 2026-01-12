#### A08:2025 - Yazılım ve Veri Bütünlüğü Hataları

Bu kategori, bir uygulama kritik verileri (kod güncellemeleri, nesne serileştirme verileri vb.) doğrulama yapmadan kabul ettiğinde ortaya çıkar.

#### Temel Risk Belirtileri:

**İmzasız Güncellemeler:** Uygulamanın, üreticiden geldiğini doğrulamadan bir .jar veya .exe dosyasını indirip çalıştırması.

**Güvensiz Deserialization:** Dışarıdan gelen bir veri paketinin (Java Object, JSON, XML) doğrudan nesneye dönüştürülmesi sırasında zararlı kod çalıştırılması.

**CI/CD Pipeline Güvenliği:** Derleme (build) sürecine müdahale edilerek kodun içine gizlice "backdoor" eklenmesi.

**Veri Bütünlüğü Kontrolü Eksikliği:** Veritabanındaki veya bir dosyadaki verinin yolda değiştirilip değiştirilmediğinin (Hash/Checksum) kontrol edilmemesi.

#### Java Uygulamalarında Önlemler ve Kod Örnekleri

**1. Güvensiz Deserialization (Look-ahead Java Deserialization)**
Java'nın yerleşik ObjectInputStream sınıfı, nesneleri okurken sınıfları otomatik olarak yükler. Eğer saldırgan kendi hazırladığı bir sınıfı gönderirse, readObject() metodu çağrıldığı anda sisteminiz ele geçirilebilir.

Güvenli Yaklaşım (Java 9+ Filtering): Artık sadece izin verilen sınıfların (Allow-list) serileştirmeden geçmesine izin veren filtreler kullanmalıyız.

```java

import java.io.*;

public class IntegritySafeReader {

    public Object readSecureObject(InputStream inputStream) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(inputStream);

        // Filtre: Sadece kendi model sınıflarımıza ve java.lang içindeki temel tiplere izin ver
        // "!*" geri kalan her şeyi reddet.
        ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
            "com.abc.models.*;java.base/java.lang.*;!*");

        ois.setInternalObjectInputFilter(filter);

        return ois.readObject();
    }
}

```

**2. Dijital İmza Doğrulama (Digital Signature)**
Dışarıdan bir dosya veya konfigürasyon paketi alıyorsanız, bunun gerçekten sizin tarafınızdan (veya güvenilir bir partnerden) imzalandığını RSA gibi algoritmalarla doğrulamalısınız.

```java

import java.security.*;

public class SignatureVerifier {

    public boolean isFileIntegrityValid(byte[] data, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        // SHA256 ile RSA kullanarak imza doğrulaması başlat
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(data);

        // İmza veri ile uyuşuyor mu?
        return signature.verify(signatureBytes);
    }
}

```

**3. Dosya Bütünlüğü Kontrolü (Checksum/Hash)**
İndirilen veya yüklenen dosyaların transfer sırasında bozulmadığını veya değiştirilmediğini doğrulamak için SHA-256 hash kontrolü yapmalısınız.

```java

import java.nio.file.*;
import java.security.MessageDigest;

public class HashChecker {

    public static String calculateChecksum(String filePath) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] fileBytes = Files.readAllBytes(Paths.get(filePath));
        byte[] hashBytes = digest.digest(fileBytes);

        // Hash'i okunabilir hex formatına çevir
        StringBuilder hexString = new StringBuilder();
        for (byte b : hashBytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }
}

```

#### A08 İçin Mimari Tavsiyeler

**JSON/XML Kullanın:** Mümkünse Java'nın yerleşik Serializable yapısını kullanmaktan kaçının. JSON (Jackson/Gson) gibi formatlar çok daha güvenlidir çünkü kod yürütme (code execution) yetenekleri kısıtlıdır.

**Otomatik Güncelleme Mekanizmaları:** Eğer kendi güncelleme mekanizmanızı yazıyorsanız, indirilen dosyayı çalıştırmadan önce mutlaka kod imzalama (code signing) kontrolü yapın.

**Pipeline Güvenliği:** GitHub Actions veya Jenkins gibi CI/CD araçlarında kullanılan "third-party action" veya "plugin"lerin versiyonlarını sabit tutun (tag yerine commit hash kullanın).

**Bütünlük Kontrolü:** Önemli verileri saklarken (örneğin kullanıcı bakiyesi veya yetkiler), verinin yanında bir HMAC (Hash-based Message Authentication Code) saklayarak verinin veritabanında manipüle edilmesini engelleyebilirsiniz.
