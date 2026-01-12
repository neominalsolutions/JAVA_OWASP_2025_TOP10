#### A06:2025 - Güvensiz Tasarım

Bu zafiyet, uygulama geliştirilmeye başlanmadan önce güvenlik gereksinimlerinin belirlenmemesi veya yanlış kurgulanmasıdır. Yazılım mükemmel (hatasız) kodlanmış olsa bile, tasarım mantığı sakat olduğu için saldırıya açıktır.

### Temel Risk Belirtileri:

**Eksik Tehdit Modelleme:** Olası saldırı senaryolarının tasarım aşamasında düşünülmemesi.

**İş Mantığı Hataları:** Örneğin; bir e-ticaret sitesinde ürün miktarını -1 girerek bakiyeyi artırabilmek.

**Güvensiz Varsayılanlar:** Yeni açılan hesapların otomatik olarak "Admin" yetkisiyle gelmesi.

**Hassas Akışların Korunmaması:** Şifre sıfırlama veya ödeme gibi kritik adımların botlara veya brute-force saldırılarına karşı tasarlanmamış olması.

#### NET Uygulamalarında Tasarım Seviyesinde Önlemler

**1. İş Mantığı Doğrulaması (Fail-Safe Design)**
Tasarımınız, "negatif" veya "beklenmedik" durumları her zaman en güvenli şekilde ele almalıdır.

```csharp
// KÖTÜ TASARIM
public void UpdateBalance(long userId, decimal amount)
{
    var user = _repository.FindById(userId);

    // HATA: 'amount' negatif gelirse (-500 gibi), toplama işlemi
    // aslında bakiyeyi düşürür. Bu bir "Business Logic" açığıdır.
    user.Balance += amount;

    _repository.Save(user);
}

// Savunmacı Tasarım (Defensive Design in .NET Core)

public void UpdateBalance(long userId, decimal amount)
{
    // 1. Guard Clause: Girdi doğrulaması
    if (amount <= 0)
    {
        // Parametre adını (nameof) belirtmek debug ve logging için kritiktir.
        throw new ArgumentOutOfRangeException(nameof(amount), "İşlem tutarı sıfırdan büyük olmalıdır.");
    }

    // 2. Varlık Kontrolü
    var user = _repository.GetById(userId);
    if (user == null)
    {
        throw new KeyNotFoundException($"ID'si {userId} olan kullanıcı sistemde mevcut değil.");
    }

    // 3. İş Mantığı Kontrolü (Örn: Maksimum bakiye limiti)
    const decimal MaxBalance = 1000000;
    if (user.Balance + amount > MaxBalance)
    {
        throw new InvalidOperationException("Maksimum bakiye limiti aşılamaz.");
    }

    // 4. State Değişimi
    user.Balance += amount;

    _repository.Update(user);
}


```

**2. Hız Sınırlama (Rate Limiting) Tasarımı:**

Kritik endpoint'leri (Login, OTP gönderimi, Şifre Sıfırlama) tasarlarken bir saldırganın bu endpoint'i milyonlarca kez çağıramayacağından emin olmalısınız.

```csharp

using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

// 1. Rate Limiting Servislerini Kaydet
builder.Services.AddRateLimiter(options =>
{
    options.AddFixedWindowLimiter(policyName: "LoginLimiter", opt =>
    {
        opt.Window = TimeSpan.FromMinutes(1); // 1 dakikalık pencere
        opt.PermitLimit = 5;                  // Maksimum 5 istek
        opt.QueueLimit = 0;                   // Limit dolunca kuyruğa alma, direkt reddet
        opt.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
    });

    // Limit aşıldığında dönecek hata kodunu belirle (Varsayılan 503'tür, 429 daha doğrudur)
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
});

var app = builder.Build();

// 2. Middleware'i etkinleştir (Routing'den sonra, Auth'dan önce)
app.UseRouting();
app.UseRateLimiter();
app.UseAuthorization();

```

**3. En Az Yetki Prensibi (Least Privilege) ve RBAC**

Tasarım, her kullanıcının sadece kendi işini yapabileceği en dar yetki setine sahip olmasını zorunlu kılmalıdır.

```csharp

[ApiController]
[Route("api/orders")]
public class OrderController : ControllerBase
{
    private readonly IOrderService _service;

    public OrderController(IOrderService service)
    {
        _service = service;
    }

    [HttpGet("{id}")]
    [Authorize(Roles = "USER")] 
    public async Task<IActionResult> GetOrder(long id)
    {
        var order = await _service.FindByIdAsync(id);

        if (order == null) return NotFound();

        // Tasarım Kontrolü: Sahiplik doğrulaması (BOLA/IDOR Koruması)
        // .NET'te NameIdentifier genellikle 'Subject' (sub) veya 'UserId' claim'ine eşittir.
        var currentUserId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (order.UserId != currentUserId)
        {
            // Güvenlik İpucu: 403 (Forbid) yerine 404 dönmek,
            // saldırgana o ID'de bir sipariş olup olmadığı bilgisini vermez.
            return Forbid();
        }

        return Ok(order);
    }
}

```

### Güvenli Tasarım" Checklist:

**Shift Left:** Güvenliği kod yazdıktan sonra değil, mimariyi çizerken tartışın (Threat Modeling).
**Secure Defaults:** Tüm özellikler varsayılan olarak "kapalı" veya "en kısıtlı yetkiyle" gelmelidir.
**Separation of Concerns:** UI, Business Logic ve Data katmanlarını birbirinden kesin çizgilerle ayırın.
**Trust Boundary:** Dış dünyadan gelen (Frontend, Mobile, Third-party) hiçbir veriye asla güvenmeyin.
