#### A10:2025 - İstisnai Durumların Hatalı Yönetimi

OWASP Top 10 2025 listesine yeni giren A10:2025 - Mishandling of Exceptional Conditions (İstisnai Durumların Hatalı Yönetimi), uygulamanın beklenen akış dışındaki (hata, sistem kesintisi, beklenmedik girdi vb.) durumları nasıl ele aldığına odaklanır.

Bu kategori, yazılımın stres altında veya beklenmedik bir durumla karşılaştığında güvenli bir şekilde "çökememesi" durumunu kapsar.

#### Temel Risk Belirtileri:

**Hassas Bilgi Sızıntısı:** Hata mesajlarında (Stack Trace) veritabanı yapısı, kütüphane versiyonları veya kullanıcı verilerinin açık edilmesi.

**Açık Kalma (Fail-Open):** Bir hata oluştuğunda sistemin erişimi kısıtlamak yerine (örneğin auth servisi çöktüğünde) herkese izin vermesi.

**Hizmet Dışı Bırakma (DoS):** Yakalanmayan istisnaların (Exceptions) sistem kaynaklarını (bellek, CPU) tüketerek uygulamayı kilitlemesi.

**Tutarsız Durumlar:** Bir hata sonrası işlemin yarıda kalması ve veritabanında veya bellek durumunda tutarsızlık oluşması (Race Conditions).

### NET Uygulamalarında Önlemler ve Kod Örnekleri

**1. Global İstisna Yönetimi ve Bilgi Sızıntısını Önleme**

Kullanıcıya asla teknik detay içeren bir hata sayfası göstermemelisiniz. Spring Boot'ta @ControllerAdvice kullanarak tüm hataları merkezi bir noktada yakalayıp son kullanıcıya anonim bir mesaj dönebilirsiniz.

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
        // 1. Teknik detayı logla (Sadece dahili loglarda kalır)
        var traceId = httpContext.TraceIdentifier;
        _logger.LogError(exception, "Hata oluştu. TraceId: {TraceId}", traceId);

        // 2. Kullanıcıya dönecek anonim mesajı hazırla (Information Leakage engellenir)
        var response = new
        {
            Error = "Bir sistem hatası oluştu.",
            ReferenceCode = traceId
        };

        httpContext.Response.StatusCode = StatusCodes.Status500InternalServerError;

        await httpContext.Response.WriteAsJsonAsync(response, cancellationToken);

        return true; // Hata başarıyla ele alındı
    }
}
```

**2. Güvenli Kapanma (Fail-Closed / Fail-Secure)**

Kritik bir kontrol (örneğin yetkilendirme kontrolü) sırasında hata alınırsa, sistem varsayılan olarak "Erişim Reddedildi" durumuna geçmelidir.

```csharp

// HATALI TASARIM: Hata durumunda kapı açık kalıyor!
public bool IsUserAuthorized(string userId)
{
    try
    {
        return _authService.CheckPermission(userId);
    }
    catch (Exception ex)
    {
        // HATA: Servis yanıt vermediğinde veya bir hata fırlattığında
        // true dönerek sistemi savunmasız bırakıyoruz.
        _logger.LogError(ex, "Yetki servisi hatası.");
        return true;
    }
}

// GÜVENLİ TASARIM
// DOĞRU TASARIM: Şüphe durumunda erişimi reddet!
public bool IsUserAuthorized(string userId)
{
    try
    {
        return _authService.CheckPermission(userId);
    }
    catch (Exception ex)
    {
        // 1. Hatayı detaylıca logla (TraceId ile)
        _logger.LogCritical(ex, "Kritik yetkilendirme hatası! Kullanıcı: {UserId}", userId);

        // 2. Varsayılan olarak erişimi reddet (Fail-Closed)
        // Kullanıcıya "Erişim Reddedildi" mesajı gider, ancak sistem güvenli kalır.
        return false;
    }
}


```

**3. Circuit Breaker**, bu hatanın sistemin geneline yayılmasını (cascading failure) engelleyen sigortadır.

- Senaryo: Yetki servisi yavaşladı veya çöktü. Circuit Breaker devreye girer (Open state) ve o servise istek atmayı keser.
- Devre açıldığında (Open State) çalışacak olan "Fallback" metodunun ne yapacağı, Fail-Closed veya Fail-Open kararıdır.

Bir Circuit Breaker kullanarak nasıl Fail-Closed bir yapı kuracağımızı görelim:

```csharp

using Polly;
using Polly.CircuitBreaker;
using System.Net.Http;

var builder = WebApplication.CreateBuilder(args);

// Polly Pipeline Tanımlama
builder.Services.AddResiliencePipeline("AuthPolicy", pipelineBuilder =>
{
    pipelineBuilder
        // 1. Fallback: Devre açıkken veya hata alındığında çalışacak "Fail-Closed" mantığı
        .AddFallback(new FallbackStrategyOptions<bool>
        {
            FallbackAction = _ => Outcome.FromResult(false), // Güvenlik gereği REDDET
            OnFallback = args =>
            {
                Console.WriteLine("Fallback devreye girdi: Erişim reddedildi.");
                return default;
            }
        })
        // 2. Circuit Breaker
        .AddCircuitBreaker(new CircuitBreakerStrategyOptions<bool>
        {
            FailureRatio = 0.5, // %50 hata eşiği
            SamplingDuration = TimeSpan.FromSeconds(30), // Sliding window süresi
            MinimumThroughput = 5, // Hesaplama için min arama sayısı
            BreakDuration = TimeSpan.FromSeconds(30), // Open state bekleme süresi

            // Yavaş yanıt (Slow Call) yönetimi
            ShouldHandle = new PredicateBuilder<bool>()
                .Handle<HttpRequestException>()
                .Handle<TimeoutException>(),

            // Half-Open durumunda test amaçlı istek sayısı
            OnOpened = args => Console.WriteLine("Devre AÇILDI (Sistem kilitlendi)"),
            OnClosed = args => Console.WriteLine("Devre KAPANDI (Sistem normale döndü)")
        });
});


public class SecurityAuthorizationService
{
    private readonly ILogger<SecurityAuthorizationService> _logger;
    private readonly ResiliencePipeline<bool> _pipeline;
    private readonly IRemoteAuthClient _remoteAuthClient;

    public SecurityAuthorizationService(
        ILogger<SecurityAuthorizationService> logger,
        ResiliencePipelineProvider<string> pipelineProvider,
        IRemoteAuthClient remoteAuthClient)
    {
        _logger = logger;
        _remoteAuthClient = remoteAuthClient;
        // Program.cs'de tanımladığımız "AuthPolicy"yi alıyoruz
        _pipeline = pipelineProvider.GetPipeline<bool>("AuthPolicy");
    }

    public async Task<bool> CheckUserAccess(string userId, string resourceId)
    {
        // Pipeline üzerinden güvenli bir şekilde çağrı yapıyoruz
        return await _pipeline.ExecuteAsync(async token =>
        {
            // Bu asıl iş mantığıdır; hata veya yavaşlık durumunda
            // yukarıdaki Fallback (false dönen kısım) otomatik çalışır.
            return await _remoteAuthClient.HasPermission(userId, resourceId);
        });
    }
}

```

**4. Kaynak Yönetimi ve DoS Koruması (Try-with-Resources)**

İstisnai bir durum oluştuğunda açık kalan veritabanı bağlantıları veya dosya akışları sistemin çökmesine neden olabilir. Net her zaman using kullanın!

```csharp

public void ProcessSensitiveFileLegacy(string path)
{
    using (StreamReader reader = new StreamReader(path))
    {
        string line = reader.ReadLine();
        // reader bu blok sonunda otomatik olarak Dispose edilir.
    }
}

```

**5. Null Pointer Dereference (Null Kontrolü)**

A10 altındaki en yaygın CWE'lerden (CWE-476) biridir. Beklenmedik bir null değeri uygulamanın beklenmedik şekilde çökmesine neden olur.

```csharp

public void ProcessUser(User? user)
{
    var profileId = user?.Profile?.Id;

    if (profileId != null)
    {
        _logger.LogInformation("Profil bulundu: {ProfileId}", profileId);
    }
    else
    {
        _logger.LogWarning("Profil bulunamadı, güvenli işlem başlatılıyor.");
    }
}

```

#### A10 İçin Genel Checklist

**Hata Politikası:** Uygulamanın her katmanında (Controller, Service, DB) hataların nasıl yakalanacağını standartlaştırın.

**Log Temizliği:** Hata loglarına asla kullanıcı şifresi, kredi kartı veya API anahtarı gibi verileri düşürmeyin.

**Default Deny:** Güvenlik kontrollerinde her zaman "önce reddet, sonra izin ver" mantığını tasarım seviyesinde (A06 ile bağlantılı) uygulayın.

**Resilience:** Dış servislere bağımlılıklarda Circuit Breaker (Polly gibi) kullanarak, servis çöktüğünde uygulamanın ana akışının bozulmamasını sağlayın.
