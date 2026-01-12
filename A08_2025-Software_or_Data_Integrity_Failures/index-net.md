#### A08:2025 - Yazılım ve Veri Bütünlüğü Hataları

Bu kategori, bir uygulama kritik verileri (kod güncellemeleri, nesne serileştirme verileri vb.) doğrulama yapmadan kabul ettiğinde ortaya çıkar.

#### Temel Risk Belirtileri:

**İmzasız Güncellemeler:** Uygulamanın, üreticiden geldiğini doğrulamadan bir .jar veya .exe dosyasını indirip çalıştırması.

**Güvensiz Deserialization:** Dışarıdan gelen bir veri paketinin (NET Object, JSON, XML) doğrudan nesneye dönüştürülmesi sırasında zararlı kod çalıştırılması.

**CI/CD Pipeline Güvenliği:** Derleme (build) sürecine müdahale edilerek kodun içine gizlice "backdoor" eklenmesi.

**Veri Bütünlüğü Kontrolü Eksikliği:** Veritabanındaki veya bir dosyadaki verinin yolda değiştirilip değiştirilmediğinin (Hash/Checksum) kontrol edilmemesi.

#### NET Uygulamalarında Önlemler ve Kod Örnekleri

**1. Güvensiz Deserialization (Look-ahead NET Deserialization)**

"Insecure Deserialization" riskleri, C# tarafında yıllarca BinaryFormatter üzerinden yaşandı. Ancak Microsoft, .NET 8 ve 9 ile bu konuda radikal bir karar alarak bu sınıfı tamamen "tehlikeli" ilan etti ve varsayılan olarak devre dışı bıraktı.

Ancak modern dünyada asıl çözüm, binary serileştirmeden tamamen kaçıp JSON veya Protobuf gibi "contract-based" yapılara geçmektir.

```csharp

using System;
using System.Runtime.Serialization;

public class AllowListSerializationBinder : SerializationBinder
{
    public override Type BindToType(string assemblyName, string typeName)
    {
        // Sadece izin verilen sınıfların (Allow-list) yüklenmesine müsaade et
        if (typeName.StartsWith("MyProject.Models.") || typeName == "System.String")
        {
            return Type.GetType($"{typeName}, {assemblyName}");
        }

        // Listede olmayan her şey için güvenlik ihlali fırlat
        throw new SecurityException($"Güvenlik Uyarısı: '{typeName}' sınıfının serileştirmeden geçmesine izin verilmiyor!");
    }
}

```

**2. Dijital İmza Doğrulama (Digital Signature)**
Dışarıdan bir dosya veya konfigürasyon paketi alıyorsanız, bunun gerçekten sizin tarafınızdan (veya güvenilir bir partnerden) imzalandığını RSA gibi algoritmalarla doğrulamalısınız.

```csharp

using System.Security.Cryptography;

public class SignatureVerifier
{
    /// <summary>
    /// Verinin bütünlüğünü ve kaynağını RSA imza doğrulaması ile kontrol eder.
    /// </summary>
    public bool IsFileIntegrityValid(byte[] data, byte[] signatureBytes, RSA rsaPublicKey)
    {

        // Eğer modern bir sistemle konuşuyorsanız Pss dolgusu da kullanılabilir.
        return rsaPublicKey.VerifyData(
            data,
            signatureBytes,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1
        );
    }
}
```

**3. Dosya Bütünlüğü Kontrolü (Checksum/Hash)**
İndirilen veya yüklenen dosyaların transfer sırasında bozulmadığını veya değiştirilmediğini doğrulamak için SHA-256 hash kontrolü yapmalısınız.

1. Modern ve Performanslı Yaklaşım (Önerilen)
Bu yöntem dosyayı belleğe yüklemez, parça parça okuyarak hash hesaplar. Büyük dosyalar için idealdir.

```csharp

using System.Security.Cryptography;

public static class HashChecker
{
    public static string CalculateChecksum(string filePath)
    {
        // SHA256 nesnesini oluştur
        using var sha256 = SHA256.Create();
        
        // Dosyayı bir Stream olarak aç (Bellek dostu)
        using var stream = File.OpenRead(filePath);
        
        // Hash'i hesapla
        byte[] hashBytes = sha256.ComputeHash(stream);

        // .NET 5+ ile gelen en hızlı Hex çevirme yöntemi
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }
}

// eğer dosya küçük ise

public static string CalculateChecksumQuick(string filePath)
{
    byte[] fileBytes = File.ReadAllBytes(filePath);
    byte[] hashBytes = SHA256.HashData(fileBytes); // .NET 6+ ile gelen static metot
    
    return Convert.ToHexString(hashBytes).ToLowerInvariant();
}


```

#### A08 İçin Mimari Tavsiyeler

**JSON/XML Kullanın:** System.Text.JSON gibi formatlar çok daha güvenlidir çünkü kod yürütme (code execution) yetenekleri kısıtlıdır.

**Otomatik Güncelleme Mekanizmaları:** Eğer kendi güncelleme mekanizmanızı yazıyorsanız, indirilen dosyayı çalıştırmadan önce mutlaka kod imzalama (code signing) kontrolü yapın.

**Pipeline Güvenliği:** GitHub Actions veya Jenkins gibi CI/CD araçlarında kullanılan "third-party action" veya "plugin"lerin versiyonlarını sabit tutun (tag yerine commit hash kullanın).

**Bütünlük Kontrolü:** Önemli verileri saklarken (örneğin kullanıcı bakiyesi veya yetkiler), verinin yanında bir HMAC (Hash-based Message Authentication Code) saklayarak verinin veritabanında manipüle edilmesini engelleyebilirsiniz.
