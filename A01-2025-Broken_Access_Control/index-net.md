#### A01:2025 Broken Access Control

Kullanıcıların yetkileri dışındaki verilere veya işlevlere erişmesini engelleyen politikadır. Bu kontroller bozulduğunda; saldırganlar yetkisiz veri ifşası, verilerin değiştirilmesi veya silinmesi gibi ciddi işlemler yapabilirler.

#### Yaygın Zafiyet Örnekleri

**1. En Az Yetki İlkesinin İhlali:**

Kullanıcılara varsayılan olarak kapalı olması gereken özelliklerin açık bırakılması.

**2. IDOR:**

URL'deki bir kullanıcı ID'sini değiştirerek başkasının hesabına erişmek (IDOR).

**3. API Yetkilendirme Eksikliği:**

API'lerin POST, PUT veya DELETE gibi kritik işlemlerde yetki kontrolü yapmaması.

**4. Metadata Manipülasyonu:**

JWT (JSON Web Token) veya çerezlerin (cookie) değiştirilerek yetki yükseltilmesi (Privilege Escalation).

**5. CORS Hataları:**

Yanlış yapılandırılmış CORS politikaları nedeniyle güvenilmeyen kaynakların API'ye erişmesi.

```csharp

// Vulnerable Kod


builder.Services.AddCors(options =>
{
    options.AddPolicy("BadCorsPolicy", policy =>
    {
        policy.SetIsOriginAllowed(_ => true) // TEHLİKE: Herhangi bir origin'i kabul eder (*)
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials(); // TEHLİKE: Origin wildcard iken credential izni
    });
});

var app = builder.Build();
app.UseCors("BadCorsPolicy"); // Middleware sıralaması kritiktir
// Güvenli Cors Ayarları

// Program.cs
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCors(options =>
{
    options.AddPolicy("SecureCorsPolicy", policy =>
    {
        policy.WithOrigins("https://abc.com", "https://admin.abc.com") // Sadece güvenilir domainler
              .WithMethods("GET", "POST", "PUT") // Sadece gerekli metodlar
              .WithHeaders("Authorization", "Content-Type") // İzin verilen headerlar
              .AllowCredentials() // Güvenli origin ile birlikte kullanılabilir
              .SetPreflightMaxAge(TimeSpan.FromHours(1)); // 3600 saniye cache (maxAge)
    });
});

var app = builder.Build();

// ÖNEMLİ: UseCors, UseRouting'den sonra, UseAuthorization'dan önce gelmelidir.
app.UseRouting();
app.UseCors("SecureCorsPolicy");
app.UseAuthorization();


```

---

#### IDOR Zafiyet Örnekleri

**1. Parametre Zafiyeti:**

Uygulama SQL içerisine hesap bilgilerine erişmek için doğrulanmamış bir veri gönderir.

```csharp

// .NET karşılığı:
using (var connection = new SqlConnection(connectionString))
{
    var query = "SELECT * FROM Accounts WHERE AccountId = @acct";
    var command = new SqlCommand(query, connection);

    // Parametre atama (SQL Injection koruması sağlar)
    command.Parameters.AddWithValue("@acct", Request.Query["acct"].ToString());

    connection.Open();

    using (SqlDataReader reader = command.ExecuteReader())
    {
        while (reader.Read())
        {
            // Verilere erişim: reader["ColumnName"]
            var balance = reader["Balance"];
        }
    }
}

```

**2. Forced Browsing:**

Burada saldırgan, uygulama arayüzünde (UI) kendisine gösterilmeyen ancak tahmin edilebilir olan URL'lere doğrudan gitmeye çalışır.

```bash

https://example.com/app/getappInfo (Normal kullanıcı sayfası)

https://example.com/app/admin_getappInfo (Admin sayfası - Tahmin edilen)

```

**3. İstemci Taraflı Güvenlik**

Uygulama, admin butonlarını gizlemek için JS kullanır. Saldırgan tarayıcıda butonu görmez ama API ucunu (endpoint) bildiği için tarayıcıyı değil, doğrudan komut satırını kullanır:

```bash

curl https://example.com/app/admin_getappInfo

```

\*\* Not: 2025 güncellemesi ile, SSRF (sunucu üzerinden başka bir sunucuya yetkisiz istek atma) vakaları da artık bu kategorinin altında birer "Broken Access Control" örneği sayılıyor.

```csharp

// TEHLİKELİ: URL parametresi hiçbir kontrolden geçmiyor.
// Saldırgan: "http://169.254.169.254/latest/meta-data/" yazarak AWS IAM Role bilgilerini çalabilir.
public async Task FetchUserResource(string urlString)
{
    using (var client = new HttpClient())
    {
        // Sunucu, dışarıdan gelen URL'e sorgusuz sualsiz istek atar.
        var response = await client.GetAsync(urlString);
        var content = await response.Content.ReadAsStringAsync();
    }
}

```

---

#### Broker Access Control Açıkları Nasıl Önlenir?

**1. Varsayılan Olarak Reddet (Deny by Default):**

Kamuya açık kaynaklar dışındaki her şey için erişim varsayılan olarak kapalı olmalıdır.

**2. Sunucu Taraflı Kontrol:**

Erişim kontrolleri asla istemci tarafında (JavaScript) değil, sunucu tarafında güvenilir kodla yapılmalıdır.

**3. Sahiplik Kontrolü:**

Sadece "kullanıcı giriş yaptı mı?" diye bakılmamalı, erişilen verinin o kullanıcıya ait olup olmadığı (kayıt sahipliği) kontrol edilmelidir.

**4. Hız Sınırlama (Rate Limiting):**

Otomatik saldırı araçlarını engellemek için API ve kontrolcü erişimlerine limit konulmalıdır.

**5. Başarısız ve Şüpheli Durumları Loglama:**

Başarısız erişim denemeleri mutlaka kaydedilmeli ve şüpheli durumlarda yöneticilere uyarı gönderilmelidir.

**6. Güvenli Token Yönetimi**

Kaynağa erişmlerin kritik durumlarda engellenmesinin sağlanması gerekir.

Erişimin sonlandırılmasını gerektiren dört temel senaryo vardır:

#### Token İptal Yöntemleri

Tokenların teknik yapısına göre iki farklı yöntem izlenir:

**1. Veritabanı Tabanlı Tokenlar (Stateful):**

Tokenlar bir veritabanında saklanıyorsa işlem kolaydır. İlgili kullanıcıya veya uygulamaya ait token kayıtları veritabanından silinir.

Kaynak sunucusu (API), her istekte tokenı veritabanından kontrol ettiği için erişim anında kesilir.

**2. Kendi Kendini Doğrulayan Tokenlar (Stateless - Örn: JWT):**

Bu tokenlar sunucuya sormadan doğrulandığı için iptal edilmeleri zordur.

1. Tokenların süresinin çok kısa tutulması ve süresi dolduğunda yeni token verilmemesi.

2. (Revocation List): İptal edilen tokenların ID'lerinin (jti) bir "kara liste"de tutulması ve sunucunun her istekte bu listeyi kontrol etmesi.

3. Uygulamanın Yenileme Tokenlarının (Refresh Tokens) iptal edilmesi; böylece mevcut kısa ömürlü erişim tokenı bittiğinde uygulama yeni bir tane alamaz.

---

#### IDOR ATAKLARINA KARŞI GÜVENLİK YÖNTEMLERİ

#### Attribute Based Access Control

**ABAC (Attribute-Based Access Control):** Erişim kararları niteliklere (kullanıcı departmanı, işlem saati, veri sahipliği) göre verilir. Daha esnektir ve IDOR (Insecure Direct Object Reference) riskini azaltmakta çok daha etkilidir.

### Neden Bu Yaklaşımı Kullanmalıyız ?

**1. Merkezi Güvenlik Mantığı:**

Yarın bir gün "Dökümanları sadece mesai saatlerinde düzenleyebilirler" diye bir kural gelirse, sadece Evaluator sınıfını değiştirmen yeterli olur.

**2. IDOR Koruması:**

Kullanıcının sadece giriş yapmış olması yetmez; nesnenin öznitelikleri (owner, department) ile kullanıcının öznitelikleri dinamik olarak eşleşmek zorundadır.

**3. Test Edilebilirlik:**

Güvenlik mantığı POJO bir sınıf içinde olduğu için Unit Test yazmak çok kolaydır.

```csharp

public record Document(string Id, string Title, string Owner, string Department);

// Yetki gereksinimi (Spring'deki 'WRITE' veya 'READ' string'i yerine geçer)
public class DocumentOperationRequirement : IAuthorizationRequirement
{
    public string Name { get; }
    public DocumentOperationRequirement(string name) => Name = name;
}

public static class DocumentOperations
{
    public static DocumentOperationRequirement Write = new("WRITE");
    public static DocumentOperationRequirement Read = new("READ");
}


public class DocumentAuthorizationHandler : AuthorizationHandler<DocumentOperationRequirement, Document>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        DocumentOperationRequirement requirement,
        Document resource)
    {
        var currentUser = context.User.Identity?.Name;

        // Mantık 1: Döküman sahibi mi?
        bool isOwner = resource.Owner == currentUser;

        // Mantık 2: Departman admini mi? (Claim kontrolü)
        // Spring: "ROLE_" + doc.getDepartment() + "_ADMIN"
        string requiredRole = $"ROLE_{resource.Department}_ADMIN";
        bool isDeptAdmin = context.User.IsInRole(requiredRole);

        if (requirement.Name == "WRITE")
        {
            if (isOwner || isDeptAdmin) context.Succeed(requirement);
        }
        else if (requirement.Name == "READ")
        {
            context.Succeed(requirement); // Okuma herkese açık veya ek mantık
        }

        return Task.CompletedTask;
    }
}


var builder = WebApplication.CreateBuilder(args);

// Handler'ı DI konteynırına kaydet
builder.Services.AddSingleton<IAuthorizationHandler, DocumentAuthorizationHandler>();

builder.Services.AddAuthorization(options =>
{
    // Opsiyonel: İsimlendirilmiş bir policy olarak da kaydedebilirsiniz
    options.AddPolicy("EditDocumentPolicy", policy =>
        policy.Requirements.Add(DocumentOperations.Write));
});

```

---

#### Broken Access Control Açıkığından Korunmak İçin WEB Güvenlik Testleri

**1. Path Traversal (Dizin Geçişi) Testi**

Path Traversal (Dizin Geçişi), bir saldırganın uygulama tarafından kısıtlanan dizinlerin dışına çıkmak için ../ (nokta-nokta-slash) gibi karakter dizilerini kullanarak sunucudaki hassas dosyalara (konfigürasyon dosyaları, şifreler, kaynak kodlar) erişmesidir.

Özetle; uygulamanın sadece "A" klasörüne bakması gerekirken, saldırganın sistemi kandırıp "C" klasöründeki dosyaları okutmasıdır.

##### Nasıl Engellenir?

Sadece "içinde .. var mı?" diye bakmak yetmez (çünkü encoding oyunları yapılabilir). En sağlam yöntem, dosya yolunu normalize etmek (canonicalization) ve beklenen güvenli klasörün altında kalıp kalmadığını kontrol etmektir.

```csharp

// Kullanıcıdan gelen "fileName" doğrudan kullanılıyor.
// Giriş: "../../../etc/passwd" olursa sistem bunu okur.
// TEHLİKELİ: Kullanıcı "fileName" ile dizin dışına çıkabilir.
public FileInfo GetFile(string fileName)
{
    string baseDirectory = "/var/www/images";
    // Path.Combine güvenlik sağlamaz, sadece string birleştirir!
    string filePath = Path.Combine(baseDirectory, fileName);

    return new FileInfo(filePath);
}

```

```csharp

using System;
using System.IO;
using System.Security;

public class FileService
{
    // Path.DirectorySeparatorChar ile işletim sistemi uyumluluğunu (Windows/Linux) garantiye alıyoruz.
    private static readonly string BaseDirectory = Path.GetFullPath("/var/www/images" + Path.DirectorySeparatorChar);

    public string GetSecurePath(string userInputFileName)
    {
        // 1. Kullanıcı girdisini al ve ana dizinle birleştir
        string combinedPath = Path.Combine(BaseDirectory, userInputFileName);

        // 2. Yolu NORMALIZE et (toRealPath + normalize karşılığı)
        // Bu işlem ../ gibi tüm dizin aşımı ifadelerini çözümler ve tam yolu oluşturur.
        string resolvedPath = Path.GetFullPath(combinedPath);

        // 3. Güvenlik Kontrolü
        // Çözülen yolun hala ana dizinle başlayıp başlamadığını kontrol et.
        // StringComparison.OrdinalIgnoreCase ile case-sensitivity (büyük/küçük harf) risklerini önlüyoruz.
        if (!resolvedPath.StartsWith(BaseDirectory, StringComparison.OrdinalIgnoreCase))
        {
            throw new SecurityException("Geçersiz dosya yolu! Dizin dışına çıkma denemesi saptandı.");
        }

        return resolvedPath;
    }
}
```

---

**2. Yetkilendirme Şemasını Atlatma Testi**

Bu testin temel amacı, uygulamanın kullanıcı rollerini ve veri sahipliğini sunucu tarafında (backend) sıkı bir şekilde kontrol edip etmediğini doğrulamaktır.

```csharp

// Bu kodda sadece kullanıcının giriş yapıp yapmadığı kontrol ediliyor (Authentication). Ancak, istenen siparişin o kullanıcıya ait olup olmadığı kontrol edilmiyor (Authorization Bypass).

[HttpGet("api/orders/{orderId}")]
[Authorize] // Sadece giriş yapmış olmayı kontrol eder
public async Task<IActionResult> GetOrderDetails(long orderId)
{
    // TEHLİKE: Sadece ID ile sorgu yapılıyor.
    // Saldırgan orderId=101 yerine 102 yazarak başkasının verisini çekebilir.
    var order = await _context.Orders.FindAsync(orderId);

    if (order == null) return NotFound();

    return Ok(order);
}


```

Güvenli yaklaşımda, veritabanından veri çekilirken mevcut oturumdaki kullanıcı bilgisiyle (Principal) verinin sahibi karşılaştırılmalıdır.

```csharp

[HttpGet("api/orders/{orderId}")]
[Authorize]
public async Task<IActionResult> GetSecureOrderDetails(long orderId)
{
    // 1. Giriş yapmış kullanıcının ID'sini Claim'ler üzerinden al
    var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

    if (string.IsNullOrEmpty(userId)) return Unauthorized();

    // 2. Sorguya "Sahiplik Kontrolü" ekle (UserId filtresi)
    // Bu sayede saldırgan başka bir ID gönderse bile sonuç "null" dönecektir.
    var order = await _context.Orders
        .FirstOrDefaultAsync(o => o.Id == orderId && o.UserId == userId);

    if (order == null)
    {
        // Güvenlik İpucu: 403 Forbidden yerine 404 NotFound dönmek,
        // saldırgana o ID'de bir veri olup olmadığı bilgisini vermez (Obscurity).
        return NotFound("Sipariş bulunamadı veya erişim yetkiniz yok.");
    }

    return Ok(order);
}
```

---

**3. Yetki Yükseltme (Privilege Escalation) Testi**

Bu, bir kullanıcının kendisine tanımlanan izinlerin ötesine geçerek, erişmemesi gereken yetkilere veya verilere ulaşması durumudur.

İki ana türü vardır:

Dikey Yetki Yükseltme (Vertical): Düşük yetkili bir kullanıcının (örneğin standart kullanıcı), daha yüksek yetkili birinin (örneğin admin) fonksiyonlarına erişmesi.

Yatay Yetki Yükseltme (Horizontal): Aynı yetki seviyesindeki bir kullanıcının, başka bir kullanıcının verilerine erişmesi (Örn: A kullanıcısının B kullanıcısının siparişlerini görmesi).

```csharp

// Vulnerable Kod
// kullanıcının admin olup olmadığını istekle gelen bir parametreye bakarak kontrol ediyor.

[HttpPost("api/admin/delete-account")]
public IActionResult DeleteAccount([FromQuery] long accountId, [FromQuery] string userRole)
{
    // TEHLİKE: İstemciden gelen "userRole" parametresine güveniliyor.
    // Saldırgan bu isteği Fiddler veya Burp Suite ile yakalayıp
    // "userRole=USER" kısmını "userRole=ADMIN" olarak değiştirebilir.
    if (userRole == "ADMIN")
    {
        _accountService.Delete(accountId);
        return Ok("Hesap silindi.");
    }

    return Forbid("Yetkisiz işlem!");
}

// Güvenli Kod
// Güvenli bir sistemde, yetki bilgisi asla istemciden (client) alınmaz. Bunun yerine, sunucu tarafında güvenli bir şekilde saklanan oturum (session) veya doğrulanmış bir JWT (JSON Web Token) içerisinden okunur.

[HttpPost("api/admin/delete-account")]
// .NET'in yerleşik [Authorize] özniteliği, rol kontrolünü merkezi olarak yapar.
// Bu öznitelik, User.IsInRole("ADMIN") kontrolünü otomatikleştirir.
[Authorize(Roles = "ADMIN")]
public IActionResult DeleteAccount([FromQuery] long accountId)
{
    // Artık parametre olarak 'userRole' almamıza gerek yok.
    // Eğer istek bu metoda ulaştıysa, kullanıcının 'ADMIN' rolüne sahip olduğu
    // sunucu tarafından (JWT içindeki Claims üzerinden) zaten kanıtlanmıştır.

    _accountService.Delete(accountId);
    return Ok("Hesap silindi.");
}

```

---

**4. IDOR Testi:**

Bir uygulamanın veritabanı anahtarları, dosya isimleri veya cihaz ID'leri gibi nesnelere erişmek için kullanıcı tarafından sağlanan girdileri (genellikle URL parametreleri veya form alanları) kullanması ve bu esnada sunucu tarafında bir yetkilendirme kontrolü yapmaması durumudur.

```csharp

// Bu kodda uygulama, kullanıcıdan gelen invoiceId değerini körü körüne kabul eder. Kullanıcının giriş yapmış olması (Authentication) yeterli sayılır, ancak faturanın sahibi olup olmadığı sorgulanmaz.

[HttpGet("api/invoices/{invoiceId}")]
[Authorize] // Sadece "token geçerli mi?" diye bakar.
public async Task<IActionResult> GetInvoice(long invoiceId)
{
    // TEHLİKE: Sorgu sadece ID üzerinden yapılıyor.
    // Saldırgan, giriş yaptıktan sonra URL'deki 101'i 102 yaparak
    // başkasına ait faturayı görebilir.
    var invoice = await _context.Invoices.FindAsync(invoiceId);

    if (invoice == null)
        return NotFound("Fatura bulunamadı.");

    return Ok(invoice);
}

// Güvenli
// veritabanı sorgusuna hem fatura ID'sini hem de mevcut kullanıcının ID'sini dahil ederiz. Böylece fatura başkasına aitse sonuç boş döner.

[HttpGet("api/invoices/{invoiceId}")]
[Authorize]
public async Task<IActionResult> GetSecureInvoice(long invoiceId)
{
    // 1. JWT içinden kullanıcının ID'sini veya Username'ini çekiyoruz.
    // Claims içindeki 'NameIdentifier' (genelde userId) veya 'Name' (username) kullanılır.
    var currentUsername = User.Identity?.Name;

    if (string.IsNullOrEmpty(currentUsername))
        return Unauthorized();

    // 2. Güvenli Sorgu: Hem fatura ID'sini hem de sahibi kontrol et.
    // SELECT * FROM Invoices WHERE Id = @id AND OwnerUsername = @user
    var invoice = await _context.Invoices
        .FirstOrDefaultAsync(i => i.Id == invoiceId && i.OwnerUsername == currentUsername);

    if (invoice == null)
    {
        // Güvenlik İpucu: 403 Forbidden dönmek yerine 404 NotFound dönmek,
        // saldırgana o ID'de bir fatura olup olmadığı bilgisini sızdırmaz.
        return NotFound("Fatura bulunamadı veya erişim yetkiniz yok.");
    }

    return Ok(invoice);
}

```

---

**5. OAuth Zayıflıkları Testi**

OAuth testleri, bir saldırganın kullanıcı oturumlarını çalmasını, hesapları ele geçirmesini (Account Takeover) veya yetkisiz verilere erişmesini sağlayan yapılandırma hatalarını bulmayı hedefler.

#### Kritik Test Noktaları:

**1. Redirect URI Doğrulaması:**

Saldırganın redirect_uri parametresini değiştirerek yetkilendirme kodunu (code) veya token'ı kendi sunucusuna yönlendirip yönlendiremediği kontrol edilir.

**2. State Parametresi (CSRF Koruması):**

İstemci ile sunucu arasında rastgele bir state değerinin taşınıp taşınmadığına bakılır. Bu değer yoksa, saldırgan kurbanın hesabını kendi hesabıyla ilişkilendirebilir.

**3. Token Sızıntısı:**

Access token veya Code'un URL fragmanlarında, Referer başlıklarında veya tarayıcı geçmişinde sızıp sızmadığı test edilir.

**4. PKCE (Proof Key for Code Exchange) Eksikliği:**

Özellikle mobil ve SPA uygulamalarında, kodun çalınmasını önleyen PKCE mekanizmasının uygulanıp uygulanmadığı kontrol edilir.

```csharp

// Güvenli olmayan Kod: State parametresi doğrulanmıyor

[HttpGet("callback")]
public async Task<IActionResult> HandleCallback([FromQuery] string code, [FromQuery] string state)
{
    // TEHLİKE: State doğrulaması yok!
    // TEHLİKE: Redirect_uri kontrolü yapılmıyor.

    // Kod kullanılarak token değişimi yapılıyor (Güvensiz)
    var token = await _oAuthService.ExchangeCodeForToken(code);
    return Redirect($"/dashboard?token={token}");
}

// Güvenli Kod:

// En güvenli yöntem, Spring Security OAuth2 Client gibi olgun kütüphaneleri kullanmaktır. Bu kütüphaneler state yönetimini ve PKCE desteğini otomatik sağlar.

// Eğer manuel bir kontrol yapmanız gerekiyorsa mantık mutlaka aşağıdaki gibi olmalıdır:

[HttpGet("login/oauth2")]
public IActionResult InitiateLogin()
{
    // 1. Benzersiz bir state (nonce) oluştur
    string state = Guid.NewGuid().ToString("N");

    // 2. State'i güvenli bir şekilde Session'da sakla
    // Not: Session yerine şifrelenmiş bir Cookie de kullanılabilir.
    HttpContext.Session.SetString("oauth_state", state);

    // 3. Güvenli URL oluştur
    var authUrl = "https://provider.com/oauth/authorize?" +
                  "client_id=my-client-id" +
                  "&redirect_uri=https://abc.com/callback" +
                  $"&state={state}" +
                  "&response_type=code";

    return Redirect(authUrl);
}

[HttpGet("callback")]
public async Task<IActionResult> HandleCallback([FromQuery] string code, [FromQuery] string state)
{
    // 4. GELEN STATE İLE KAYDEDİLENİ KIYASLA
    var savedState = HttpContext.Session.GetString("oauth_state");

    if (string.IsNullOrEmpty(savedState) || savedState != state)
    {
        // CSRF saldırısı veya session aşımı durumu
        return BadRequest("CSRF Saldırısı saptandı veya oturum geçersiz! State uyuşmuyor.");
    }

    // 5. State kullanıldı, hemen temizle (Replay Attack önlemi)
    HttpContext.Session.Remove("oauth_state");

    // Token değişimi işlemleri...
    return Redirect("/dashboard");
}
```

---

#### Savunma Stratejileri

**1. Strict Redirect URI:**

Yetkilendirme sunucusunda (Authorization Server) yönlendirme adreslerini tam URL olarak kaydedin (https://app.com/callback). Asla joker karakter (https://app.com/*) kullanmayın.

**2. State Parametresi Şart:**

Her istekte benzersiz, tahmin edilemez bir state kullanın.

**3. PKCE Kullanın:**

Modern OAuth 2.1 standartlarına göre, sadece mobil değil, web uygulamalarında da PKCE (Proof Key for Code Exchange) kullanmak artık standarttır.

**4. Kısa Ömürlü Tokenlar:**

Access token ömürlerini kısa tutun ve mutlaka Refresh Token mekanizmasını güvenli bir şekilde (HttpOnly cookie) kurgulayın.

---

**6. Yetkilendirme Sunucusu Zayıflıkları Testi**

**Temel Test Alanları:**

**1. Kayıt ve Kimlik Doğrulama:**

Yeni istemciler (apps) kaydedilirken Client ID ve Client Secret güvenli mi oluşturuluyor? Kayıt işlemi sırasında hız sınırlama (rate limiting) var mı?

**2. Redirect URI (Yönlendirme Adresi) Doğrulaması:**

Sunucu, gelen isteği önceden kaydedilmiş olan adrese göre tam eşleşme (strict match) yaparak mı kontrol ediyor? (Joker karakter kullanımı en büyük risklerden biridir).

**3. Grant Type (İzin Türü) Yönetimi:**

Sunucu, güvenli olmayan (örneğin Implicit Flow) yöntemleri hala destekliyor mu? Gereksiz yere açık bırakılmış grant type'lar saldırı yüzeyini artırır.

**4. Token/Kod Yaşam Döngüsü:**

Yetkilendirme kodları (authorization codes) tek kullanımlık mı? Erişim token'ları (Access Tokens) çalındığında iptal (revocation) mekanizması düzgün çalışıyor mu?

**5. PKCE Zorunluluğu:**

Sunucu, özellikle halka açık istemciler (SPA, mobil) için PKCE'yi zorunlu tutuyor mu?

---

**7. OAuth İstemci Zayıflıkları Testi**

**Temel Test Alanları:**

**1. Lack of State Parameter (CSRF):**

Eğer istemci state parametresini kullanmıyorsa veya doğrulamıyorsa, saldırgan kurbanın oturumuna kendi hesabını "bağlayabilir".

**2. Insecure Storage of Client Secret:**

client_secret asla JavaScript (Frontend) kodunda, mobil uygulama paketinde veya GitHub gibi herkese açık yerlerde saklanmamalıdır.

**3. Token Leakage (Referer Headers):**

Yetkilendirme kodu (code) veya token içeren URL'ler, dış bağlantılara (örneğin bir reklam görseline) tıklandığında Referer başlığı ile üçüncü taraflara sızabilir.

**Öneri:** OAuth callback sayfalarında kesinlikle no-referrer veya same-origin security header kullanılmalıdır.

**4. Insufficient Token Validation:**

İstemci, aldığı ID Token veya Access Token'ın imzasını (signature), süresini (expiry) ve kendisine ait olup olmadığını (audience) kontrol etmelidir.

**5. Sensitive Information in URL:**

Hassas verilerin URL fragmanlarında (#) veya parametrelerde taşınması, tarayıcı geçmişinde sızıntıya yol açar.
