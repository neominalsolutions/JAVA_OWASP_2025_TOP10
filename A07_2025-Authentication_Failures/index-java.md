#### A07:2025 - Kimlik Doğrulama Hataları Özeti

Bu kategori, bir kullanıcının kimliğinin doğrulanması (Authentication) ve oturum yönetimi (Session Management) süreçlerindeki hataları kapsar.

#### Temel Risk Belirtileri:

**Brute Force & Credential Stuffing:** Saldırganların binlerce şifre denemesine izin verilmesi.

**Zayıf Şifre Politikaları:** Kolay tahmin edilebilir şifrelere izin verilmesi.

**MFA Eksikliği:** Kritik uygulamalarda Çok Faktörlü Kimlik Doğrulama'nın (Multi-Factor Authentication) olmaması.

**Güvensiz Oturum Yönetimi:** Session ID'lerin URL'de taşınması, çıkış yapıldığında oturumun geçersiz kılınmaması veya "Remember Me" özelliklerinin zayıf şifrelenmesi.

**Session Fixation:** Saldırganın önceden bildiği bir Session ID'yi kullanıcıya dayatabilmesi.

#### Java Uygulamalarında Önlemler ve Kod Örnekleri

**1. Brute Force Koruması (Login Throttling)**
Spring Security'de oturum açma denemelerini sınırlamak için yerleşik bir mekanizma olsa da, genellikle özelleştirilmiş bir AuthenticationFailureHandler veya bir "Login Attempt Service" kullanmak daha sağlıklıdır.

Örnek: Başarısız Denemeleri Takip Eden Servis Mantığı

```java

@Service
public class LoginAttemptService {
    private final int MAX_ATTEMPT = 5;
    private LoadingCache<String, Integer> attemptsCache;

    public LoginAttemptService() {
        attemptsCache = CacheBuilder.newBuilder()
            .expireAfterWrite(1, TimeUnit.DAYS).build(new CacheLoader<>() {
                public Integer load(String key) { return 0; }
            });
    }

    public void loginFailed(String key) {
        int attempts = attemptsCache.getUnchecked(key);
        attemptsCache.put(key, ++attempts);
    }

    public boolean isBlocked(String key) {
        return attemptsCache.getUnchecked(key) >= MAX_ATTEMPT;
    }
}

// Spring Security'nin fırlattığı olayları yakalayan listener.

@Component
public class AuthenticationEventListener {

    private final LoginAttemptService loginAttemptService;
    private final HttpServletRequest request;

    public AuthenticationEventListener(LoginAttemptService loginAttemptService, HttpServletRequest request) {
        this.loginAttemptService = loginAttemptService;
        this.request = request;
    }

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        loginAttemptService.loginSucceeded(getClientIP());
    }

    @EventListener
    public void onFailure(AuthenticationFailureBadCredentialsEvent event) {
        loginAttemptService.loginFailed(getClientIP());
    }

    private String getClientIP() {
        // Proxy/Load Balancer arkasındaysanız gerçek IP'yi almak için
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }
}

```

**2. Güvenli Oturum Yönetimi (Session Management)**

Spring Security yapılandırmasında oturum sabitleme (Session Fixation) saldırılarını engellemek ve oturum güvenliğini sıkılaştırmak kritiktir.

```java

@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .sessionManagement(session -> session
            // Kullanıcı login olduğunda her zaman yeni bir Session ID oluşturur
            .sessionFixation().migrateSession()
            // Aynı anda sadece tek bir aktif oturuma izin ver (Opsiyonel)
            .maximumSessions(1)
            .expiredUrl("/login?expired")
        )
        .logout(logout -> logout
            .deleteCookies("JSESSIONID") // Çıkışta cookie'yi sil
            .invalidateHttpSession(true) // Oturumu tamamen geçersiz kıl
        );
    return http.build();
}

```

**3. Hassas Şifre Politikası ve Validasyon**

Kullanıcıdan sadece "en az 8 karakter" istemek yetmez. Modern standartlar, şifrenin yaygın kullanılanlar listesinde olmadığını kontrol etmeyi önerir.

```java

public class PasswordPolicyValidator {

    // Regex ile karmaşıklık kontrolü: En az bir büyük, bir küçük, bir rakam, bir özel karakter
    private static final String PASSWORD_PATTERN =
        "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!])(?=\\S+$).{12,}$";

    public boolean isValid(String password) {
        if (password == null) return false;
        return password.matches(PASSWORD_PATTERN);
    }
}

```

**4. Cookie Güvenliği (HttpOnly ve Secure)**
Oturum çerezlerinin (Session Cookies) çalınmasını zorlaştırmak için her zaman HttpOnly ve Secure flag'lerini kullanmalısınız.

```bash

server.servlet.session.cookie.http-only=true
server.servlet.session.cookie.secure=true
server.servlet.session.cookie.same-site=strict

```

#### A07 İçin Modern Standartlar

**Passkey / MFA Geçişi:** Mümkünse sadece şifreye güvenmeyin. Google Authenticator (TOTP) veya WebAuthn (Passkey) desteği ekleyin.

**Credential Stuffing Kontrolü:** Kullanıcı şifresini belirlerken, Have I Been Pwned gibi API'ler üzerinden şifrenin daha önce sızdırılıp sızdırılmadığını kontrol edin.

**Hatalı Giriş Mesajları:** Kullanıcıya "Şifre yanlış" veya "Kullanıcı adı bulunamadı" gibi spesifik bilgiler vermeyin. Bunun yerine her zaman: "Kullanıcı adı veya şifre hatalı" mesajını kullanın.
