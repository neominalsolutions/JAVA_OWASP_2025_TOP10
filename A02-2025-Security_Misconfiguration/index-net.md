### A02:2025 - Güvenlik Yapılandırma Hataları

Bu kategori, bir uygulamanın her katmanında (bulut servisleri, sunucu, veritabanı, framework, kütüphaneler) güvenliğin yanlış veya eksik yapılandırılmasını kapsar.

### Temel Risk Belirtileri:

**Gereksiz Özellikler**
Kullanılmayan portların, servislerin, sayfaların veya hesapların açık bırakılması.

**Varsayılan Ayarlar**
Varsayılan kullanıcı adları/şifrelerin değiştirilmemesi.

**Hata Yönetimi**
Hata mesajlarında stack trace (yığın izi) gibi hassas sistem bilgilerinin son kullanıcıya gösterilmesi.

**Eksik Güvenlik Başlıkları**
HTTP yanıtlarında Security Headers (HSTS, CSP, X-Frame-Options vb.) bulunmaması.

**Bulut Hataları**
S3 bucket'ların veya veritabanı portlarının internete açık olması.

### Net Uygulamalarında Önlemler ve Kod Örnekleri

**1. Hata Mesajlarını Gizleme (Stack Trace Koruması)**
Uygulamanız çöktüğünde kullanıcıya asla kod yapısını ifşa eden mesajlar göstermemelisiniz.

```csharp

using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

public class GlobalExceptionHandler : IExceptionHandler
{
    private readonly ILogger<GlobalExceptionHandler> _logger;

    public GlobalExceptionHandler(ILogger<GlobalExceptionHandler> logger)
    {
        _logger = logger;
    }

    public async ValueTask<bool> TryHandleAsync(
        HttpContext httpContext,
        Exception exception,
        CancellationToken cancellationToken)
    {
        // 1. Hatayı logla (Sadece içerde kalsın)
        _logger.LogError(exception, "Beklenmeyen bir hata oluştu: {Message}", exception.Message);

        // 2. Kullanıcıya dönecek güvenli, steril mesajı hazırla
        // .NET dünyasında standart hata formatı 'ProblemDetails' (RFC 7807) kullanılır.
        var problemDetails = new ProblemDetails
        {
            Status = StatusCodes.Status500InternalServerError,
            Title = "Sistem Hatası",
            Detail = "İşleminiz sırasında teknik bir sorun oluştu. Lütfen destek ekibine başvurun.",
            Extensions = new Dictionary<string, object?>
            {
                { "timestamp", DateTime.UtcNow }
            }
        };

        // 3. Response'u yapılandır
        httpContext.Response.StatusCode = problemDetails.Status.Value;
        await httpContext.Response.WriteAsJsonAsync(problemDetails, cancellationToken);

        // 'true' dönerek hatanın burada işlendiğini ve pipeline'da başka yere gitmemesi gerektiğini belirtiyoruz.
        return true;
    }
}

var builder = WebApplication.CreateBuilder(args);

// Exception handler'ı DI konteynırına kaydet
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddProblemDetails(); // RFC 7807 desteği için

var app = builder.Build();

// ÖNEMLİ: Middleware sıralamasında en üstte olmalı
app.UseExceptionHandler();

app.MapControllers();
app.Run();

```

---

**2. Güvenli HTTP Başlıklarını (Security Headers) Yapılandırma**

Net Core varsayılan olarak birçok başlığı middleware olarak ekler ancak bunları projenize göre sıkılaştırmanız gerekir.

```csharp

var builder = WebApplication.CreateBuilder(args);

// HSTS Ayarları 
builder.Services.AddHsts(options =>
{
    options.Preload = true;
    options.IncludeSubDomains = true;
    options.MaxAge = TimeSpan.FromDays(365); // 31536000 saniye
});

var app = builder.Build();

// 1. HSTS Middleware'ini etkinleştir (Sadece Production ortamında önerilir)
if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

// 2. HTTPS Yönlendirmesini zorunlu kıl
app.UseHttpsRedirection();

// 3. Custom Security Headers (Clickjacking ve CSP karşılığı)
app.Use(async (context, next) =>
{
    // Clickjacking Koruması
    context.Response.Headers.Append("X-Frame-Options", "DENY");

    // Content Security Policy
    context.Response.Headers.Append("Content-Security-Policy",
        "default-src 'self'; script-src 'self' https://trusted.com;");

    // Ekstra Güvenlik: XSS Koruması ve MIME Sniffing önleme
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("X-XSS-Protection", "1; mode=block");

    await next();
});

app.MapControllers();
app.Run();
```

**3. XML ve JSON İşleyicilerini Güvenli Hale Getirme (XXE Önleme)**
.NET dünyasında XML işlemleri için en performanslı ve güvenli yol XmlReader ve XmlReaderSettings ikilisini kullanmaktır.

```csharp

using System.Xml;

public void SecureXmlParsing(string xmlInput)
{
    // 1. Güvenlik ayarlarını tanımla
    XmlReaderSettings settings = new XmlReaderSettings
    {
        
        // DTD kullanımını tamamen yasaklar. En güvenli yöntemdir.
        DtdProcessing = DtdProcessing.Prohibit,

        
        // Dış kaynakların (URL veya dosya yolu) çözümlenmesini engeller.
        XmlResolver = null,

        // XML içinde aşırı büyük nesnelerle yapılacak DoS saldırılarını (Billion Laughs) engeller.
        MaxCharactersFromEntities = 1024
    };

    // 2. Ayarlarla birlikte okuyucuyu oluştur
    using (StringReader sr = new StringReader(xmlInput))
    using (XmlReader reader = XmlReader.Create(sr, settings))
    {
        while (reader.Read())
        {
            // XML işleme mantığı burada yer alır
        }
    }
}

```

**4. Hassas Verilerin Yapılandırma Dosyalarında Saklanmaması**

Şifreleri veya API anahtarlarını application.properties içinde düz metin olarak saklamak büyük bir hatadır. Bunun yerine ortam değişkenleri (Environment Variables) veya Vault gibi araçlar kullanılmalıdır.

```csharp


// 1. Seviye: Yerel Geliştirme (Local Development) -> User Secrets
// .NET'te asla appsettings.json içine yazılmamalıdır. Bunun yerine .NET'e özgü User Secrets kullanılır.
dotnet user-secrets init
dotnet user-secrets set "ConnectionStrings:DefaultConnection" "Server=myServer;Password=TopSecret123!"


// 2. Seviye Secret Manager
var builder = WebApplication.CreateBuilder(args);

// Üretim ortamında (Production) sırları Key Vault'tan çek
if (builder.Environment.IsProduction())
{
    var keyVaultEndpoint = new Uri(builder.Configuration["VaultUri"]!);
    builder.Configuration.AddAzureKeyVault(keyVaultEndpoint, new DefaultAzureCredential());
}

var app = builder.Build();

```

### Genel Tavsiyeler (Checklist)

**Otomasyon:**
Altyapınızı (Terraform, Ansible vb.) kullanarak kurulumları otomatikleştirin; manuel ayarlar hata riskini artırır.

**Gereksiz Paketleri Kaldırın:**
Üretim (Production) ortamında Swagger UI, H2 Console veya test endpoint'lerini mutlaka kapatın.

**Güncel Kalın**
Kullanılan framework (Spring, Hibernate vb.) ve kütüphanelerin güvenlik yamalarını takip edin.

**Sıkılaştırma (Hardening):**
Uygulama sunucusunun (Tomcat, Jetty) varsayılan "Server" başlığını (Örn: Server: Apache-Coyote/1.1) gizleyin.
