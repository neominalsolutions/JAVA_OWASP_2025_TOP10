#### A09:2025 - Güvenlik Günlüğü ve Uyarı Hataları

Bu zafiyet, saldırıları tespit etme, müdahale etme ve adli analiz yapma yeteneğinin olmamasıdır. Çoğu veri ihlalinde, saldırganların sistemde fark edilmeden ortalama 200 günden fazla kaldığı görülmektedir.

#### Temel Risk Belirtileri:

**Görünmezlik** Başarısız girişler, yetki aşımı denemeleri ve girdi doğrulama hatalarının loglanmaması.

**Yetersiz İçerik:** Logların kim, ne zaman, nerede ve hangi işlem sorularına cevap vermemesi.

**Lokal Depolama:** Logların sadece sunucu içinde tutulması (Saldırgan içeri girdiğinde ilk iş logları siler).

**Uyarı Eksikliği:** Kritik bir güvenlik olayı olduğunda kimseye bildirim gitmemesi.

### NET Uygulamalarında Önlemler ve Kod Örnekleri

**1. Serilog LogContext ile İzlenebilirlik**

Sadece "Hata oluştu" yazmak yetmez. O hatayı hangi kullanıcı, hangi istek (Trace ID) ile yaptı? LogContext, bu veriyi tüm log satırlarına otomatik ekler.

**Örnek:** SecurityLoggingMiddleware

```csharp


using Serilog.Context;

public class SecurityLoggingMiddleware
{
    private readonly RequestDelegate _next;

    public SecurityLoggingMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // 1. Verileri Hazırla
        var userId = context.User.Identity?.IsAuthenticated == true
                     ? context.User.Identity.Name
                     : "ANONYMOUS";

        // .NET her istek için otomatik bir TraceIdentifier (Correlation ID) üretir.
        var traceId = context.TraceIdentifier;
        var clientIp = context.Connection.RemoteIpAddress?.ToString();

        // 2. LogContext içine it (Push)
        // 'using' bloğu sonunda bu property'ler otomatik olarak loglardan silinir (MDC.clear)
        using (LogContext.PushProperty("UserId", userId))
        using (LogContext.PushProperty("TraceId", traceId))
        using (LogContext.PushProperty("ClientIp", clientIp))
        {
            // İşlemi boru hattındaki bir sonraki middleware'e aktar
            await _next(context);
        }
    }
}

```

**2. Spring Security Audit Events (Denetim Günlükleri)**
Başarılı/başarısız login denemelerini manuel loglamak yerine Spring'in yerleşik AbstractAuthenticationAuditListener yapısını kullanmalısın.

```csharp

builder.Services.AddAuthentication().AddJwtBearer(options =>
{
    options.Events = new JwtBearerEvents
    {
        OnAuthenticationFailed = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogWarning("SECURITY_EVENT: Auth hatası! {Message}", context.Exception.Message);
            return Task.CompletedTask;
        },
        OnForbidden = context =>
        {
            // Yetkisiz erişim loglama
        _logger.LogError("SECURITY_EVENT: Yetkisiz erişim reddedildi! Kullanıcı: {Username} - Kaynak: {Resource}",
            notification.Username, notification.Resource);
            return Task.CompletedTask;
        }
    };
});

```

**3. Yapılandırılmış Loglama (JSON Format)**
Modern log analiz araçları (ELK, Splunk, Graylog) düz metin yerine JSON formatını tercih eder. Bu, loglar üzerinde kolayca sorgu (Örn: "Son 1 saatte 50'den fazla başarısız login olan IP'leri getir") yapmanı sağlar.

```csharp

var builder = WebApplication.CreateBuilder(args);

// Serilog Yapılandırması
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .Enrich.FromLogContext() 
    .Enrich.WithProperty("ApplicationName", "ABC-Service")
    .Enrich.WithProperty("Environment", builder.Environment.EnvironmentName)
    // Çıktıyı JSON formatında konsola veya ağa bas
    .WriteTo.Console(new RenderedCompactJsonFormatter())
    .WriteTo.Http("http://logstash-server:8080", queueLimitBytes: null) 
    .CreateLogger();

builder.Host.UseSerilog(); // Default logger'ı Serilog ile değiştir

```

#### Alerting (Uyarı) Stratejisi

**Kritik Hatalar (5xx)** Anlık Bildirim **Slack / Teams**
**Brute Force Belirtisi** IP Engelleme / Alert **Sentinel / Fail2Ban**
**Anormal Veri Çıkışı** Dashboard + Email **Grafana / Prometheus**
**Admin İşlemleri** Audit Trail (Silinemez Log) **AWS CloudWatch / Azure Monitor**

**Tavsiye:**

Sisteminin "uyarı" mekanizmasını test etmek için bir "Game Day" düzenle. Bir ekip arkadaşın sisteme kasıtlı olarak hatalı girişler yapsın veya yetkisiz sayfalara erişmeye çalışsın. Eğer 5 dakika içinde senin telefonuna veya Slack kanalına bir uyarı düşmüyorsa, A09 zafiyetine sahipsin demektir.
