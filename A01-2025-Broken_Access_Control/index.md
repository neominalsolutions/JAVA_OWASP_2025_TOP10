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

```java

// Vulnerable Kod


@Configuration
public class BadCorsConfig implements WebMvcConfigurer {

    @Override
    public void addMapping(CorsRegistry registry) {
        registry.addMapping("/**")
                // TEHLİKE 1: Herhangi bir domain'den gelen istek kabul edilir.
                .allowedOrigins("*")
                // TEHLİKE 2: Browser'ın çerezleri göndermesine izin verilir.
                .allowCredentials(true)
                .allowedMethods("GET", "POST", "PUT", "DELETE");
    }
}

// Güvenli Cors Ayarları

@Configuration
public class SecureCorsConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**") // Sadece API uçlarını açın
                .allowedOrigins(
                    "https://abc.com",
                    "https://admin.abc.com" // Sadece belirli domainler
                )
                .allowedMethods("GET", "POST", "PUT") // Sadece ihtiyacınız olan metodlar
                .allowedHeaders("Authorization", "Content-Type")
                .allowCredentials(true)
                .maxAge(3600); // Tarayıcının pre-flight (OPTIONS) isteğini cache'leme süresi
    }
}


```

---

#### IDOR Zafiyet Örnekleri

**1. Parametre Zafiyeti:**

Uygulama SQL içerisine hesap bilgilerine erişmek için doğrulanmamış bir veri gönderir.

```java

pstmt.setString(1, request.getParameter("acct"));
ResultSet results = pstmt.executeQuery();

```

**2. Forced Browsing:**

Burada saldırgan, uygulama arayüzünde (UI) kendisine gösterilmeyen ancak tahmin edilebilir olan URL'lere doğrudan gitmeye çalışır.

```java

https://example.com/app/getappInfo (Normal kullanıcı sayfası)

https://example.com/app/admin_getappInfo (Admin sayfası - Tahmin edilen)

```

**3. İstemci Taraflı Güvenlik**

Uygulama, admin butonlarını gizlemek için JS kullanır. Saldırgan tarayıcıda butonu görmez ama API ucunu (endpoint) bildiği için tarayıcıyı değil, doğrudan komut satırını kullanır:

```bash

curl https://example.com/app/admin_getappInfo

```

\*\* Not: 2025 güncellemesi ile, SSRF (sunucu üzerinden başka bir sunucuya yetkisiz istek atma) vakaları da artık bu kategorinin altında birer "Broken Access Control" örneği sayılıyor.

```java

// TEHLİKELİ: Saldırgan "url" parametresine "http://localhost:8080/admin"
// veya "http://169.254.169.254/latest/meta-data/" (AWS Metadata) yazabilir.
public void fetchUserResource(String urlString) throws IOException {
    URL url = new URL(urlString);
    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
    InputStream is = conn.getInputStream(); // Sunucu, saldırganın istediği yere istek atar!
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

```java

@Component
public class DocumentPermissionEvaluator implements PermissionEvaluator {

    @Override
    public boolean hasPermission(Authentication auth, Object targetDomainObject, Object permission) {
        if ((auth == null) || (targetDomainObject == null) || !(permission instanceof String)) {
            return false;
        }

        // Hedef nesne tipini kontrol et
        if (targetDomainObject instanceof Document doc) {
            return checkDocumentPermission(auth, doc, (String) permission);
        }

        return false;
    }

    private boolean checkDocumentPermission(Authentication auth, Document doc, String permission) {
        String currentUser = auth.getName();

        // Mantık 1: Döküman sahibi mi? (Öznitelik Kontrolü)
        boolean isOwner = doc.getOwner().equals(currentUser);

        // Mantık 2: Departman admini mi? (Bağlamsal Kontrol)
        boolean isDeptAdmin = auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_" + doc.getDepartment() + "_ADMIN"));

        if ("WRITE".equalsIgnoreCase(permission)) {
            return isOwner || isDeptAdmin;
        }

        return "READ".equalsIgnoreCase(permission);
    }

    // ID üzerinden kontrol gereken durumlar için (targetId, targetType)
    @Override
    public boolean hasPermission(Authentication auth, Serializable targetId, String targetType, Object permission) {
        // Genelde veritabanından nesneyi çekip yukarıdaki metoda yönlendiririz.
        return false;
    }
}


@Configuration
@EnableMethodSecurity // Spring Boot 3+ için
public class MethodSecurityConfig {

    private final DocumentPermissionEvaluator documentPermissionEvaluator;

    public MethodSecurityConfig(DocumentPermissionEvaluator evaluator) {
        this.documentPermissionEvaluator = evaluator;
    }

    @Bean
    static MethodSecurityExpressionHandler methodSecurityExpressionHandler(DocumentPermissionEvaluator evaluator) {
        var handler = new DefaultMethodSecurityExpressionHandler();
        handler.setPermissionEvaluator(evaluator);
        return handler;
    }
}

@Service
public class DocumentService {

    // #doc parametresi otomatik olarak PermissionEvaluator'a gönderilir
    @PreAuthorize("hasPermission(#doc, 'WRITE')")
    public void updateDocument(Document doc) {
        // Sadece yetkisi olan buraya girebilir
        System.out.println("Döküman güncellendi: " + doc.getTitle());
    }
}

```

---

#### Broken Access Control Açıkığından Korunmak İçin WEB Güvenlik Testleri

**1. Path Traversal (Dizin Geçişi) Testi**

Path Traversal (Dizin Geçişi), bir saldırganın uygulama tarafından kısıtlanan dizinlerin dışına çıkmak için ../ (nokta-nokta-slash) gibi karakter dizilerini kullanarak sunucudaki hassas dosyalara (konfigürasyon dosyaları, şifreler, kaynak kodlar) erişmesidir.

Özetle; uygulamanın sadece "A" klasörüne bakması gerekirken, saldırganın sistemi kandırıp "C" klasöründeki dosyaları okutmasıdır.

##### Nasıl Engellenir?

Sadece "içinde .. var mı?" diye bakmak yetmez (çünkü encoding oyunları yapılabilir). En sağlam yöntem, dosya yolunu normalize etmek (canonicalization) ve beklenen güvenli klasörün altında kalıp kalmadığını kontrol etmektir.

```java

// Kullanıcıdan gelen "fileName" doğrudan kullanılıyor.
// Giriş: "../../../etc/passwd" olursa sistem bunu okur.
public File getFile(String fileName) {
    File baseDirectory = new File("/var/www/images");
    return new File(baseDirectory, fileName);
}

```

Java'nın modern java.nio.file.Path API'ı bu iş için en güvenli araçtır.

```java

import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.IOException;

public class FileService {

    private static final String BASE_DIRECTORY = "/var/www/images";

    public Path getSecurePath(String userInputFileName) throws IOException {
        // 1. Ana dizini tanımla
        Path base = Paths.get(BASE_DIRECTORY).toRealPath();

        // 2. Kullanıcı girdisiyle yolu birleştir ve NORMALIZE et (../ gibi ifadeleri çöz)
        Path resolvedPath = base.resolve(userInputFileName).normalize();

        // 3. Güvenlik Kontrolü: Çözülen yol hala ana dizinle mi başlıyor?
        if (!resolvedPath.startsWith(base)) {
            throw new SecurityException("Geçersiz dosya yolu! Dizin dışına çıkma denemesi saptandı.");
        }

        return resolvedPath;
    }
}

```

---

**2. Yetkilendirme Şemasını Atlatma Testi**

Bu testin temel amacı, uygulamanın kullanıcı rollerini ve veri sahipliğini sunucu tarafında (backend) sıkı bir şekilde kontrol edip etmediğini doğrulamaktır.

```java

Bu kodda sadece kullanıcının giriş yapıp yapmadığı kontrol ediliyor (Authentication). Ancak, istenen siparişin o kullanıcıya ait olup olmadığı kontrol edilmiyor (Authorization Bypass).

@GetMapping("/api/orders/{orderId}")
public Order getOrderDetails(@PathVariable Long orderId) {
    // Sadece kullanıcının giriş yapmış olması yetiyor, sahiplik kontrolü yok!
    // Saldırgan orderId'yi değiştirerek başkasının siparişini görebilir (Yatay Yetki Yükseltme).
    return orderRepository.findById(orderId);
}


```

Güvenli yaklaşımda, veritabanından veri çekilirken mevcut oturumdaki kullanıcı bilgisiyle (Principal) verinin sahibi karşılaştırılmalıdır.

```java

@GetMapping("/api/orders/{orderId}")
public Order getOrderDetails(@PathVariable Long orderId, Authentication authentication) {
    // 1. Mevcut giriş yapan kullanıcının adını al
    String currentUsername = authentication.getName();

    // 2. Siparişi veritabanından getir
    Order order = orderRepository.findById(orderId)
            .orElseThrow(() -> new ResourceNotFoundException("Sipariş bulunamadı"));

    // 3. YETKİLENDİRME KONTROLÜ: Sipariş bu kullanıcıya mı ait?
    if (!order.getOwnerUsername().equals(currentUsername)) {
        // Yetkisiz erişim denemesi! 403 Forbidden dönülmeli.
        throw new AccessDeniedException("Bu siparişi görüntüleme yetkiniz yok.");
    }

    return order;
}

```

```java

// Spring Security

@Service
public class OrderService {

    // Metot çalıştıktan sonra dönen nesnenin (returnObject)
    // sahibinin mevcut kullanıcı olup olmadığını kontrol eder.
    @PostAuthorize("returnObject.ownerUsername == authentication.name or hasRole('ADMIN')")
    public Order getOrderById(Long id) {
        return orderRepository.findById(id).get();
    }
}

```

---

**3. Yetki Yükseltme (Privilege Escalation) Testi**

Bu, bir kullanıcının kendisine tanımlanan izinlerin ötesine geçerek, erişmemesi gereken yetkilere veya verilere ulaşması durumudur.

İki ana türü vardır:

Dikey Yetki Yükseltme (Vertical): Düşük yetkili bir kullanıcının (örneğin standart kullanıcı), daha yüksek yetkili birinin (örneğin admin) fonksiyonlarına erişmesi.

Yatay Yetki Yükseltme (Horizontal): Aynı yetki seviyesindeki bir kullanıcının, başka bir kullanıcının verilerine erişmesi (Örn: A kullanıcısının B kullanıcısının siparişlerini görmesi).

```java

// Vulnerable Kod
// kullanıcının admin olup olmadığını istekle gelen bir parametreye bakarak kontrol ediyor.

@PostMapping("/api/admin/delete-account")
public ResponseEntity<String> deleteAccount(@RequestParam Long accountId, @RequestParam String userRole) {
    // TEHLİKELİ: Kullanıcının rolü istekle beraber geliyor!
    // Saldırgan, isteği yakalayıp "userRole=USER" yerine "userRole=ADMIN" yazabilir.
    if ("ADMIN".equals(userRole)) {
        accountService.delete(accountId);
        return ResponseEntity.ok("Hesap silindi.");
    }
    return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Yetkisiz işlem!");
}

// Güvenli Kod
// Güvenli bir sistemde, yetki bilgisi asla istemciden (client) alınmaz. Bunun yerine, sunucu tarafında güvenli bir şekilde saklanan oturum (session) veya doğrulanmış bir JWT (JSON Web Token) içerisinden okunur.

@PostMapping("/api/admin/delete-account")
// Spring Security kullanarak metod seviyesinde yetki kontrolü yapıyoruz.
@PreAuthorize("hasRole('ADMIN')")
public ResponseEntity<String> deleteAccount(@RequestParam Long accountId) {
    // Burada artık 'userRole' parametresine ihtiyacımız yok.
    // Spring Security, SecurityContext içindeki kimlik bilgilerini zaten doğruladı.

    accountService.delete(accountId);
    return ResponseEntity.ok("Hesap silindi.");
}

```

---

**4. IDOR Testi:**

Bir uygulamanın veritabanı anahtarları, dosya isimleri veya cihaz ID'leri gibi nesnelere erişmek için kullanıcı tarafından sağlanan girdileri (genellikle URL parametreleri veya form alanları) kullanması ve bu esnada sunucu tarafında bir yetkilendirme kontrolü yapmaması durumudur.

```java

// Bu kodda uygulama, kullanıcıdan gelen invoiceId değerini körü körüne kabul eder. Kullanıcının giriş yapmış olması (Authentication) yeterli sayılır, ancak faturanın sahibi olup olmadığı sorgulanmaz.

@GetMapping("/api/invoices/{invoiceId}")
public Invoice getInvoice(@PathVariable Long invoiceId) {
    // Sadece fatura ID'si ile sorgu yapılıyor.
    // Saldırgan ID'yi değiştirerek tüm şirketin faturalarını dönebilir.
    return invoiceRepository.findById(invoiceId)
            .orElseThrow(() -> new ResourceNotFoundException("Fatura bulunamadı"));
}

// Güvenli
// veritabanı sorgusuna hem fatura ID'sini hem de mevcut kullanıcının ID'sini dahil ederiz. Böylece fatura başkasına aitse sonuç boş döner.

@GetMapping("/api/invoices/{invoiceId}")
public Invoice getInvoice(@PathVariable Long invoiceId, Authentication auth) {
    String currentUsername = auth.getName();

    // SELECT * FROM invoices WHERE id = ? AND owner_username = ?
    return invoiceRepository.findByIdAndOwnerUsername(invoiceId, currentUsername)
            .orElseThrow(() -> new AccessDeniedException("Bu faturaya erişim yetkiniz yok."));
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

```java

// Güvenli olmayan Kod: State parametresi doğrulanmıyor

@GetMapping("/callback")
public String handleCallback(@RequestParam String code, @RequestParam String state) {
    // TEHLİKELİ: State parametresi doğrulanmıyor! (CSRF Risk)
    // TEHLİKELİ: Uygulama önceden kaydedilmiş redirect_uri ile gelen isteği kıyaslamıyor.

    // Kod kullanılarak token alınıyor...
    String accessToken = oauthService.exchangeCodeForToken(code);
    return "redirect:/dashboard?token=" + accessToken;
}

// Güvenli Kod:

// En güvenli yöntem, Spring Security OAuth2 Client gibi olgun kütüphaneleri kullanmaktır. Bu kütüphaneler state yönetimini ve PKCE desteğini otomatik sağlar.

// Eğer manuel bir kontrol yapmanız gerekiyorsa mantık mutlaka aşağıdaki gibi olmalıdır:

@GetMapping("/login/oauth2")
public void initiateLogin(HttpServletResponse response, HttpSession session) throws IOException {
    // 1. Benzersiz bir state oluştur ve session'a kaydet
    String state = UUID.randomUUID().toString();
    session.setAttribute("oauth_state", state);

    // 2. Güvenli URL oluştur (Sadece kayıtlı redirect_uri kullanılmalı)
    String authUrl = "https://provider.com/oauth/authorize?" +
            "client_id=my-client-id" +
            "&redirect_uri=https://abc.com/callback" + // Hardcoded veya kayıtlı listeden
            "&state=" + state +
            "&response_type=code";

    response.sendRedirect(authUrl);
}

@GetMapping("/callback")
public String handleCallback(@RequestParam String code, @RequestParam String state, HttpSession session) {
    // 3. GELEN STATE İLE KAYDEDİLENİ KIYASLA
    String savedState = (String) session.getAttribute("oauth_state");
    if (savedState == null || !savedState.equals(state)) {
        throw new SecurityException("CSRF Saldırısı saptandı! State uyuşmuyor.");
    }
    session.removeAttribute("oauth_state"); // Kullanıldıktan sonra temizle

    // 4. Token değişimi işlemleri...
    return "redirect:/dashboard";
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
