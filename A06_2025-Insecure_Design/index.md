#### A06:2025 - Güvensiz Tasarım

Bu zafiyet, uygulama geliştirilmeye başlanmadan önce güvenlik gereksinimlerinin belirlenmemesi veya yanlış kurgulanmasıdır. Yazılım mükemmel (hatasız) kodlanmış olsa bile, tasarım mantığı sakat olduğu için saldırıya açıktır.

### Temel Risk Belirtileri:

**Eksik Tehdit Modelleme:** Olası saldırı senaryolarının tasarım aşamasında düşünülmemesi.

**İş Mantığı Hataları:** Örneğin; bir e-ticaret sitesinde ürün miktarını -1 girerek bakiyeyi artırabilmek.

**Güvensiz Varsayılanlar:** Yeni açılan hesapların otomatik olarak "Admin" yetkisiyle gelmesi.

**Hassas Akışların Korunmaması:** Şifre sıfırlama veya ödeme gibi kritik adımların botlara veya brute-force saldırılarına karşı tasarlanmamış olması.

#### Java Uygulamalarında Tasarım Seviyesinde Önlemler

**1. İş Mantığı Doğrulaması (Fail-Safe Design)**
Tasarımınız, "negatif" veya "beklenmedik" durumları her zaman en güvenli şekilde ele almalıdır.

```java

// Kötü Tasarım

public void updateBalance(Long userId, BigDecimal amount) {
    User user = repository.findById(userId);
    // Tasarım hatası: 'amount' negatif gelirse kullanıcıya para eklenmiş olur!
    user.setBalance(user.getBalance().add(amount));
    repository.save(user);
}

// Defensing Design

public void updateBalance(Long userId, BigDecimal amount) {
    if (amount.compareTo(BigDecimal.ZERO) <= 0) {
        throw new SecurityException("Geçersiz işlem tutarı!");
    }
    // Limit kontrolü, yetki kontrolü ve transaction yönetimi tasarımın bir parçası olmalı
    ...
}


```

**2. Hız Sınırlama (Rate Limiting) Tasarımı:**

Kritik endpoint'leri (Login, OTP gönderimi, Şifre Sıfırlama) tasarlarken bir saldırganın bu endpoint'i milyonlarca kez çağıramayacağından emin olmalısınız. Java'da Resilience4j bu iş için kullanılır.

```java

@Service
public class AuthService {

    // Tasarım kararı: Login denemesi her dakika için 5 ile sınırlıdır.
    @RateLimiter(name = "loginLimiter")
    public String login(String username, String password) {
        // Login mantığı
        return "JWT-Token";
    }
}


```

```yml
resilience4j.ratelimiter:
  instances:
    loginLimiter:
      limitForPeriod: 5
      limitRefreshPeriod: 1m
      timeoutDuration: 0
```

**3. En Az Yetki Prensibi (Least Privilege) ve RBAC**

Tasarım, her kullanıcının sadece kendi işini yapabileceği en dar yetki setine sahip olmasını zorunlu kılmalıdır.

```java

@RestController
@RequestMapping("/api/orders")
public class OrderController {

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ROLE_USER')") // Sadece User rolü
    public Order getOrder(@PathVariable Long id) {
        Order order = service.findById(id);

        // Tasarım Kontrolü: Bu sipariş gerçekten bu kullanıcıya mı ait?
        // Sadece 'Role' kontrolü yetmez, 'Ownership' (Sahiplik) kontrolü de tasarımda olmalı.
        if (!order.getUserId().equals(getCurrentUserId())) {
            throw new AccessDeniedException("Bu siparişi görme yetkiniz yok.");
        }
        return order;
    }
}

```

### Güvenli Tasarım" Checklist:

**Shift Left:** Güvenliği kod yazdıktan sonra değil, mimariyi çizerken tartışın (Threat Modeling).
**Secure Defaults:** Tüm özellikler varsayılan olarak "kapalı" veya "en kısıtlı yetkiyle" gelmelidir.
**Separation of Concerns:** UI, Business Logic ve Data katmanlarını birbirinden kesin çizgilerle ayırın.
**Trust Boundary:** Dış dünyadan gelen (Frontend, Mobile, Third-party) hiçbir veriye asla güvenmeyin.
