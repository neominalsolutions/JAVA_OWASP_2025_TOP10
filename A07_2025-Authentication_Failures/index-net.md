#### A07:2025 - Kimlik Doğrulama Hataları Özeti

Bu kategori, bir kullanıcının kimliğinin doğrulanması (Authentication) ve oturum yönetimi (Session Management) süreçlerindeki hataları kapsar.

#### Temel Risk Belirtileri:

**Brute Force & Credential Stuffing:** Saldırganların binlerce şifre denemesine izin verilmesi.

**Zayıf Şifre Politikaları:** Kolay tahmin edilebilir şifrelere izin verilmesi.

**MFA Eksikliği:** Kritik uygulamalarda Çok Faktörlü Kimlik Doğrulama'nın (Multi-Factor Authentication) olmaması.

**Güvensiz Oturum Yönetimi:** Session ID'lerin URL'de taşınması, çıkış yapıldığında oturumun geçersiz kılınmaması veya "Remember Me" özelliklerinin zayıf şifrelenmesi.

**Session Fixation:** Saldırganın önceden bildiği bir Session ID'yi kullanıcıya dayatabilmesi.

#### NET Uygulamalarında Önlemler ve Kod Örnekleri

**1. Brute Force Koruması (Login Throttling)**
Net Core'de oturum açma denemelerini sınırlamak için yerleşik bir mekanizma olsa da, genellikle özelleştirilmiş bir AuthenticationFailureHandler veya bir "Login Attempt Service" kullanmak daha sağlıklıdır.

Örnek: Başarısız Denemeleri Takip Eden Servis Mantığı

```csharp

using Microsoft.Extensions.Caching.Memory;

public class LoginAttemptService
{
    private readonly IMemoryCache _cache;
    private const int MaxAttempts = 5;
    private const int LockoutTimeDays = 1;

    public LoginAttemptService(IMemoryCache cache)
    {
        _cache = cache;
    }

    public void LoginFailed(string ip)
    {
        var attempts = GetAttempts(ip);
        attempts++;

        _cache.Set(ip, attempts, new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromDays(LockoutTimeDays)
        });
    }

    public void LoginSucceeded(string ip)
    {
        _cache.Remove(ip);
    }

    public bool IsBlocked(string ip)
    {
        return GetAttempts(ip) >= MaxAttempts;
    }

    private int GetAttempts(string ip)
    {
        return _cache.TryGetValue(ip, out int attempts) ? attempts : 0;
    }
}

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly LoginAttemptService _loginAttemptService;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public AuthController(LoginAttemptService loginAttemptService, IHttpContextAccessor httpContextAccessor)
    {
        _loginAttemptService = loginAttemptService;
        _httpContextAccessor = httpContextAccessor;
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        var clientIp = GetClientIp();

        // 1. Bloklu mu kontrol et
        if (_loginAttemptService.IsBlocked(clientIp))
        {
            return StatusCode(429, "Çok fazla başarısız deneme. Hesabınız geçici olarak askıya alındı.");
        }

        // 2. Login mantığı (Örn: Identity veya Custom)
        bool isSuccess = MyAuthLogic(request); 

        if (isSuccess)
        {
            _loginAttemptService.LoginSucceeded(clientIp);
            return Ok(new { Token = "JWT_HERE" });
        }
        else
        {
            _loginAttemptService.LoginFailed(clientIp);
            return Unauthorized("Hatalı kullanıcı adı veya şifre.");
        }
    }

    private string GetClientIp()
    {
        // Proxy/Load Balancer desteği için ForwardedHeadersMiddleware kullanılması önerilir.
        return _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }
}

```

**2. Güvenli Oturum Yönetimi (Session Management)**

Net Core  yapılandırmasında oturum sabitleme (Session Fixation) saldırılarını engellemek ve oturum güvenliğini sıkılaştırmak kritiktir.

```csharp

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        // 1. Session Fixation Koruması: .NET varsayılan olarak login sonrası 
        // yeni bir cookie ID oluşturur. Aşağıdaki ayarlar güvenliği sıkılaştırır.
        
        options.Cookie.Name = "Neominal.Auth.Session";
        options.Cookie.HttpOnly = true; // XSS'e karşı tarayıcı script erişimini engelle
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Sadece HTTPS
        options.Cookie.SameSite = SameSiteMode.Strict; // CSRF koruması için en katı mod

        // 2. Oturum Süresi ve Geçersiz Kılma
        options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
        options.SlidingExpiration = true; // Kullanıcı aktifse süreyi uzat 
        
        options.LoginPath = "/Account/Login";
        options.LogoutPath = "/Account/Logout";
        options.AccessDeniedPath = "/Account/AccessDenied";
    });

// 3. Tekil Oturum (MaximumSessions 1) Kontrolü
// .NET'te bu yerleşik bir 'switch' değildir; genellikle 'SecurityStamp' kullanılarak çözülür.
builder.Services.Configure<SecurityStampValidatorOptions>(options =>
{
    // Her 10 saniyede bir kullanıcının kimliğini (ve aktif oturumunu) kontrol et
    options.ValidationInterval = TimeSpan.FromSeconds(10);
});


[HttpPost]
public async Task<IActionResult> Logout()
{
    // .NET'te bilet tamamen geçersiz kılınır ve istemcideki cookie silinir.
    await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

    return RedirectToAction("Login", "Account");
}

```

**3. Hassas Şifre Politikası ve Validasyon**

Kullanıcıdan sadece "en az 8 karakter" istemek yetmez. Modern standartlar, şifrenin yaygın kullanılanlar listesinde olmadığını kontrol etmeyi önerir.

1. ASPNET IDENTITY

```csharp

using Microsoft.AspNetCore.Identity;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<IdentityOptions>(options =>
{
    options.Password.RequireDigit = true;           // En az bir rakam (?=.*[0-9])
    options.Password.RequiredLength = 12;           // En az 12 karakter (.{12,})
    options.Password.RequireNonAlphanumeric = true; // En az bir özel karakter (?=.*[@#$%^&+=!])
    options.Password.RequireUppercase = true;      // En az bir büyük harf (?=.*[A-Z])
    options.Password.RequireLowercase = true;      // En az bir küçük harf (?=.*[a-z])
    options.Password.RequiredUniqueChars = 1;       // En az X adet farklı karakter olmalı
});

```


2. Custom Regex

```csharp

using System.Text.RegularExpressions;

public class PasswordPolicyValidator
{
    // .NET'te Regex performansı için 'Compiled' veya 'GeneratedRegex' önerilir.
    private const string PasswordPattern = @"^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!])(?=\S+$).{12,}$";

    public bool IsValid(string password)
    {
        if (string.IsNullOrWhiteSpace(password)) return false;

        return Regex.IsMatch(password, PasswordPattern);
    }
}

```

**4. Cookie Güvenliği (HttpOnly ve Secure)**
Oturum çerezlerinin (Session Cookies) çalınmasını zorlaştırmak için her zaman HttpOnly ve Secure flag'lerini kullanmalısınız.

```csharp

using Microsoft.AspNetCore.Authentication.Cookies;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        // server.servlet.session.cookie.http-only=true
        // XSS saldırılarında JavaScript'in cookie'ye erişmesini engeller.
        options.Cookie.HttpOnly = true;

        // server.servlet.session.cookie.secure=true
        // Cookie'nin sadece HTTPS üzerinden gönderilmesini zorunlu kılar.
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;

        // server.servlet.session.cookie.same-site=strict
        // CSRF saldırılarını önlemek için cookie'nin sadece kendi domain'inden 
        // gelen isteklerle gönderilmesini sağlar.
        options.Cookie.SameSite = SameSiteMode.Strict;

        options.Cookie.Name = "YourApp.Session";
    });

var app = builder.Build();

// Middleware sırası kritiktir
app.UseAuthentication();
app.UseAuthorization();

app.Run();

```

#### A07 İçin Modern Standartlar

**Passkey / MFA Geçişi:** Mümkünse sadece şifreye güvenmeyin. Google Authenticator (TOTP) veya WebAuthn (Passkey) desteği ekleyin.

**Credential Stuffing Kontrolü:** Kullanıcı şifresini belirlerken, Have I Been Pwned gibi API'ler üzerinden şifrenin daha önce sızdırılıp sızdırılmadığını kontrol edin.

**Hatalı Giriş Mesajları:** Kullanıcıya "Şifre yanlış" veya "Kullanıcı adı bulunamadı" gibi spesifik bilgiler vermeyin. Bunun yerine her zaman: "Kullanıcı adı veya şifre hatalı" mesajını kullanın.
