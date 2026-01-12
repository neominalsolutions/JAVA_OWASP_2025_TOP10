### A05:2025 - Injection

Injection, kullanıcıdan gelen kontrol edilmemiş verinin bir komut veya sorgu içine "süzülmeden" dahil edilmesiyle oluşur. Uygulama, bu veriyi kodun bir parçası sanarak çalıştırır.

#### Temel Risk Belirtileri:

**SQL Injection:** Kullanıcı girişinin SQL sorgularına doğrudan eklenmesi.

**Komut (OS) Injection:** Uygulamanın işletim sistemi komutlarını dışarıdan gelen parametrelerle çalıştırması.

**Log Injection:** Loglara yazılan verinin manipüle edilerek izleme araçlarının (Splunk, ELK vb.) yanıltılması.

#### NET Uygulamalarında Önlemler ve Kod Örnekleri

**1. SQL Injection:** Dinamik Sorgu Yerine Parametrik Sorgu


```csharp

// TEHLİKELİ: String Interpolation ile SQL birleştirme
// Kullanıcı username yerine "' OR '1'='1" yazarsa tüm tabloyu ele geçirir.
var sql = $"SELECT * FROM Users WHERE Username = '{username}'";
var user = _context.Users.FromSqlRaw(sql).FirstOrDefault();

// GÜVENLİ: EF Core bu veriyi otomatik olarak parametreleştirir.
var user = _context.Users
    .FromSqlInterpolated($"SELECT * FROM Users WHERE Username = {username}")
    .FirstOrDefault();

```

**2. OS Command Injection:** Komut Çalıştırmadan Kaçınmak

İşletim sistemi seviyesinde komut çalıştırmak çok risklidir. Eğer mutlaka gerekiyorsa, kullanıcıdan gelen veriyi asla doğrudan içeri alma.

```csharp

// GÜVENLİ OS KOMUT ÇALIŞTIRMA

using System.Diagnostics;
using System.Text.RegularExpressions;

public void ExecuteListCommand(string fileName)
{
    // 1. Girdi Doğrulama (Allow-list / Validation)
    // Sadece güvenli karakterlere (harf, rakam, nokta, alt çizgi, tire) izin veriyoruz.
    if (!Regex.IsMatch(fileName, @"^[a-zA-Z0-9._-]+$"))
    {
        throw new UnauthorizedAccessException("Geçersiz dosya adı formatı!");
    }

    var startInfo = new ProcessStartInfo
    {
        FileName = "ls",
        ArgumentList = { "-l", fileName }, // Parametreler ayrı ayrı eklenir
        RedirectStandardOutput = true,
        UseShellExecute = false, // Kabuk (shell) kullanımını kapatmak güvenliği artırır
        CreateNoWindow = true
    };

    using (var process = Process.Start(startInfo))
    {
        // ... çıktıları okuma işlemleri
        // string result = process.StandardOutput.ReadToEnd();
        process?.WaitForExit();
    }
}

```

**3. Log Injection:** Log Dosyalarını Koruma:

Log Injection (veya CRLF Injection) saldırıları, log dosyalarını okunmaz hale getirebileceği gibi, sistem yöneticilerini sahte hata mesajlarıyla yanıltabilir. 

.NET Core dünyasında bu sorunu hem manuel temizleme (sanitization) hem de Structured Logging (Yapısal Loglama) prensipleriyle çok daha kökten çözüyoruz.

```csharp

// 1. MANUEL SANITIZE YÖNTEMI

using System.Text.RegularExpressions;

public string SanitizeForLog(string input)
{
    if (string.IsNullOrEmpty(input)) return input;

    // C#: Yeni satır ve satır başı karakterlerini güvenli bir karakterle (_) değiştiriyoruz.
    return Regex.Replace(input, @"[\r\n]", "_");
}

// Kullanım:
_logger.LogInformation("User login attempt: {Username}", SanitizeForLog(username));


// 2. STRUCTURED LOGGING YAPISI

// HATALI: String birleştirme (Injection'a açık)
_logger.LogInformation("User login: " + username); 

// DOĞRU: Parametrik Loglama
// Log kütüphaneleri bu veriyi bir 'Property' olarak işler. 
// Birçok modern log sink'i (Elasticsearch, Seq vb.) CRLF karakterlerini otomatik olarak escape eder.
_logger.LogInformation("User login attempt: {Username}", username);


```

#### INPUT Sanitization için aşağıdaki kütüphaneler güvenlidir.

**1. HTML/XSS Temizleme (Altın Standart):** Ganss.Xss

```csharp

using Ganss.Xss;

public static class SecurityUtils
{
    // Sadece belirli etiketlere izin veren bir yapı kurgulayalım
    private static readonly HtmlSanitizer Sanitizer;

    static SecurityUtils()
    {
        Sanitizer = new HtmlSanitizer();

        // Her şeyi temizle, sadece istediğimiz "Formatting" ve "Links" etiketlerini ekle
        Sanitizer.AllowedTags.Clear();
        Sanitizer.AllowedTags.Add("b");
        Sanitizer.AllowedTags.Add("i");
        Sanitizer.AllowedTags.Add("u");
        Sanitizer.AllowedTags.Add("strong");
        Sanitizer.AllowedTags.Add("em");
        Sanitizer.AllowedTags.Add("a");

        // Linkler için sadece 'href' özniteliğine izin ver
        Sanitizer.AllowedAttributes.Clear();
        Sanitizer.AllowedAttributes.Add("href");

        // Güvenlik için linklere otomatik 'nofollow' eklemek iyi bir pratiktir
        Sanitizer.FilterHtml += (s, e) =>
        {
            if (e.Helper.TagName == "a")
            {
                e.Helper.SetAttribute("rel", "nofollow");
            }
        };
    }

    public static string SanitizeHtml(string untrustedHtml)
    {
        if (string.IsNullOrWhiteSpace(untrustedHtml)) return string.Empty;
        
        return Sanitizer.Sanitize(untrustedHtml);
    }
}

```

**2. Genel Kodlama (Encoding):** 
Veriyi temizlemek yerine (karakterleri silmek), veriyi zararsız hale getirmek (kodlamak) çoğu zaman daha güvenlidir.

```csharp

using System.Text.Encodings.Web;

public class EncodingUtils
{
    public void SafeEncodingExample(string userInput)
    {

        // Örn: <script> -> &lt;script&gt;
        string safeHtml = HtmlEncoder.Default.Encode(userInput);

        // Örn: alert('XSS') -> alert('\x27XSS\x27')
        string safeJs = JavaScriptEncoder.Default.Encode(userInput);

        string safeUrl = UrlEncoder.Default.Encode(userInput);
    }
}
```


#### Injection Engellemek İçin Tavsiyeler

**Input Validation:** Gelen her veriyi (isName, isEmail, isNumeric) sıkı bir şekilde doğrula.
**Safe API:** PreparedStatement, Stored Procedures veya güvenli ORM araçlarını tercih et.
**Least Privilege:** Veritabanı kullanıcısının sadece ihtiyacı olan yetkilere (SELECT, INSERT) sahip olmasını sağla (DROP yetkisi olmasın).
**Avoid Native Queries:** Mümkünse ADO.NET Yerine Dapper MicroORM veya EF gibi ORM tooları, Native SQL'e sadece mecbur kaldığında ve parametrik olarak başvur.
