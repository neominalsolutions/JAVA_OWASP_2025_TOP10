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

### Net Uygulamalarında Önlemler ve Kod Örnekleri

**1. Parola Saklama (Hashing)**
Parolalar asla şifrelenmez (encryption), her zaman hash'lenir. MD5 veya SHA-256 yerine, "salt" (tuzlama) ve "work factor" (iş yükü) desteği olan algoritmalar kullanılmalıdır.

```csharp

using BC = BCrypt.Net.BCrypt;

public class PasswordService
{
    private const int WorkFactor = 12;

    public string HashPassword(string rawPassword)
    {
        // Otomatik tuzlama (salting) yapar ve hash'i döner
        return BC.HashPassword(rawPassword, WorkFactor);
    }

    public bool VerifyPassword(string rawPassword, string encodedPassword)
    {
        // Gelen şifre ile hash'i kıyaslar
        return BC.Verify(rawPassword, encodedPassword);
    }
}
```

**2. Güvenli Simetrik Şifreleme (AES-GCM)**

Veri saklarken (Data at Rest) AES kullanılmalıdır. Ancak AES'in ECB modu güvensizdir (aynı bloklar aynı şifreyi üretir). Modern ve güvenli olan GCM (Galois/Counter Mode) tercih edilmelidir.

```csharp

using System.Security.Cryptography;

public class EncryptionUtil
{
    private const int NonceSize = 12; // IV uzunluğu (byte)
    private const int TagSize = 16;   // Tag uzunluğu (byte) 

    public byte[] Encrypt(byte[] data, byte[] key)
    {
        // 1. Rastgele IV (Nonce) oluşturma
        byte[] nonce = new byte[NonceSize];
        RandomNumberGenerator.Fill(nonce);

        // 2. AES-GCM nesnesini başlat
        using (var aesGcm = new AesGcm(key, TagSize))
        {
            // .NET'te tag ve ciphertext ayrı buffer'lar olarak yönetilir
            byte[] tag = new byte[TagSize];
            byte[] cipherText = new byte[data.Length];

            // 3. Şifreleme işlemini gerçekleştir
            aesGcm.Encrypt(nonce, data, cipherText, tag);

            byte[] combined = new byte[NonceSize + cipherText.Length + TagSize];

            Buffer.BlockCopy(nonce, 0, combined, 0, NonceSize);
            Buffer.BlockCopy(cipherText, 0, combined, NonceSize, cipherText.Length);
            Buffer.BlockCopy(tag, 0, combined, NonceSize + cipherText.Length, TagSize);

            return combined;
        }
    }
}

```

**3. Güvenli Rastgele Sayı Üretimi**

NET tarafında System.Random sınıfı tahmin edilebilir bir algoritma kullanır ve güvenlik gerektiren işlemler (token, şifre sıfırlama linki vb.) için asla kullanılmamalıdır. Bunun yerine RandomNumberGenerator sınıfını kullanalım.

```csharp

public class TokenGenerator
{
    public string GenerateSafeToken()
    {
        // 1. 32 byte'lık (256 bit) kriptografik rastgele veri üret
        // .NET 6+ ile gelen static GetBytes metodu oldukça performanslıdır.
        byte[] bytes = RandomNumberGenerator.GetBytes(32);

        // 2. Base64 URL Safe formatına dönüştür (Padding'siz)
        return WebEncoders.Base64UrlEncode(bytes);
    }
}

```

**4. Veri İletişim Güvenliği (TLS)**


```csharp
using System.Net;

// 1. Global Seviyede Zorunlu Kılma (Legacy Approach) Uygulama ayağa kalkarken (Program.cs veya Startup.cs), tüm giden istekleri etkileyecek şekilde global bir kısıtlama getirebilirsiniz.
ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;


// 2. İstemci Özelinde Yapılandırma (Modern & Recommended) Global ayarları değiştirmek bazen iç ağdaki eski servislerle konuşurken sorun yaratabilir. Bu yüzden sadece belirli HttpClient örnekleri için protokolü kısıtlamak daha güvenli bir yaklaşımdır.

using System.Net.Http;
using System.Security.Authentication;

var handler = new HttpClientHandler
{
    // Sadece TLS 1.2 ve 1.3 protokollerine izin ver
    SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
};

using (var client = new HttpClient(handler))
{
    // Bu istemci sadece güvenli protokollerle konuşacaktır.
    var response = await client.GetAsync("https://secure-api.com");
}


```
