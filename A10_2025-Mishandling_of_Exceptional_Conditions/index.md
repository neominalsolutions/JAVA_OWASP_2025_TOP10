#### A10:2025 - İstisnai Durumların Hatalı Yönetimi

OWASP Top 10 2025 listesine yeni giren A10:2025 - Mishandling of Exceptional Conditions (İstisnai Durumların Hatalı Yönetimi), uygulamanın beklenen akış dışındaki (hata, sistem kesintisi, beklenmedik girdi vb.) durumları nasıl ele aldığına odaklanır.

Bu kategori, yazılımın stres altında veya beklenmedik bir durumla karşılaştığında güvenli bir şekilde "çökememesi" durumunu kapsar.

#### Temel Risk Belirtileri:

**Hassas Bilgi Sızıntısı:** Hata mesajlarında (Stack Trace) veritabanı yapısı, kütüphane versiyonları veya kullanıcı verilerinin açık edilmesi.

**Açık Kalma (Fail-Open):** Bir hata oluştuğunda sistemin erişimi kısıtlamak yerine (örneğin auth servisi çöktüğünde) herkese izin vermesi.

**Hizmet Dışı Bırakma (DoS):** Yakalanmayan istisnaların (Exceptions) sistem kaynaklarını (bellek, CPU) tüketerek uygulamayı kilitlemesi.

**Tutarsız Durumlar:** Bir hata sonrası işlemin yarıda kalması ve veritabanında veya bellek durumunda tutarsızlık oluşması (Race Conditions).

### Java Uygulamalarında Önlemler ve Kod Örnekleri

**1. Global İstisna Yönetimi ve Bilgi Sızıntısını Önleme**

Kullanıcıya asla teknik detay içeren bir hata sayfası göstermemelisiniz. Spring Boot'ta @ControllerAdvice kullanarak tüm hataları merkezi bir noktada yakalayıp son kullanıcıya anonim bir mesaj dönebilirsiniz.

```java

@ControllerAdvice
public class GlobalSecurityExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalSecurityExceptionHandler.class);

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, String>> handleAllExceptions(Exception ex) {
        // 1. Teknik detayı loglara yaz (içeride kalsın)
        logger.error("Sistem hatası oluştu: ", ex);

        // 2. Kullanıcıya sadece genel bir mesaj ve takip numarası dön
        Map<String, String> response = new HashMap<>();
        response.put("error", "Bir sistem hatası oluştu.");
        response.put("referenceCode", UUID.randomUUID().toString()); // Destek ekibi için ID

        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}

```

**2. Güvenli Kapanma (Fail-Closed / Fail-Secure)**

Kritik bir kontrol (örneğin yetkilendirme kontrolü) sırasında hata alınırsa, sistem varsayılan olarak "Erişim Reddedildi" durumuna geçmelidir.

```java

// HATALI TASARIM HATA DURUMUN KOD  DEVAM EDİYOR
public boolean isUserAuthorized(String userId) {
    try {
        return authService.checkPermission(userId);
    } catch (Exception e) {
        // Hata olursa (örn: servis kapalıysa) erişime izin veriliyor! (Fail-Open)
        return true;
    }
}

// GÜVENLİ TASARIM

public boolean isUserAuthorized(String userId) {
    try {
        return authService.checkPermission(userId);
    } catch (Exception e) {
        logger.error("Yetki servisine ulaşılamadı. Erişim reddedildi.", e);
        // Hata durumunda en güvenli yol girişi reddetmektir.
        return false;
    }
}


```

**3. Circuit Breaker**, bu hatanın sistemin geneline yayılmasını (cascading failure) engelleyen sigortadır.

- Senaryo: Yetki servisi yavaşladı veya çöktü. Circuit Breaker devreye girer (Open state) ve o servise istek atmayı keser.
- Devre açıldığında (Open State) çalışacak olan "Fallback" metodunun ne yapacağı, Fail-Closed veya Fail-Open kararıdır.

Java / Resilience4j ile Uygulama Örneği
Bir Circuit Breaker kullanarak nasıl Fail-Closed bir yapı kuracağımızı görelim:

```java

@Service
public class SecurityAuthorizationService {

    private static final Logger logger = LoggerFactory.getLogger(SecurityAuthorizationService.class);

    // Circuit Breaker: Servis çökerse sistemi kilitleme, fallback'e git
    @CircuitBreaker(name = "authService", fallbackMethod = "fallbackAuthorization")
    public boolean checkUserAccess(String userId, String resourceId) {
        // Uzaktaki Auth Microservice'e istek atılıyor
        return remoteAuthClient.hasPermission(userId, resourceId);
    }

    /**
     * Fallback Metodu: Circuit Breaker devreyi açtığında burası çalışır.
     * İşte buradaki kararımız "FAIL-CLOSED" tasarımıdır.
     */
    public boolean fallbackAuthorization(String userId, String resourceId, Throwable t) {
        logger.error("Auth servisi ulaşılamaz durumda! Hata: {}. Güvenlik gereği erişim REDDEDİLDİ.", t.getMessage());

        // FAIL-CLOSED: Hata anında en güvenli olanı yap ve girişi engelle.
        // Eğer burada 'true' dönseydik, FAIL-OPEN (Zafiyet) yapmış olurduk.
        return false;
    }
}

```

```yml
resilience4j:
  circuitbreaker:
    instances:
      authService: # Servis bazlı isimlendirme
        # Devrenin açılması (Open) için hata oranı eşiği (%50 hata olursa devreyi aç)
        failureRateThreshold: 50

        # Devre açıkken (Open) ne kadar beklesin? (Yarım-Açık duruma geçmeden önce)
        waitDurationInOpenState: 30s

        # İstatistiklerin tutulacağı pencere tipi ve boyutu
        # Son 10 aramaya bakarak karar verir
        slidingWindowType: COUNT_BASED
        slidingWindowSize: 10

        # Hesaplama başlaması için gereken minimum arama sayısı
        minimumNumberOfCalls: 5

        # Yarım-Açık (Half-Open) durumunda test amaçlı kaç isteğe izin verilsin?
        permittedNumberOfCallsInHalfOpenState: 3

        # Yavaş yanıt veren servisler için (Sanal bir hata olarak kabul edilir)
        slowCallRateThreshold: 100
        slowCallDurationThreshold: 2s # 2 saniyeden uzun süren istekler "yavaş" kabul edilir

        # Hangi hataların devreyi açmasını istiyoruz? (SecurityException vb.)
        recordExceptions:
          - org.springframework.web.client.HttpServerErrorException
          - java.util.concurrent.TimeoutException
          - java.io.IOException
```

**4. Kaynak Yönetimi ve DoS Koruması (Try-with-Resources)**

İstisnai bir durum oluştuğunda açık kalan veritabanı bağlantıları veya dosya akışları sistemin çökmesine neden olabilir. Java'da her zaman try-with-resources yapısını kullanın.

```java

public void processSensitiveFile(String path) {
    // try bloğu bittiğinde (hata alsa bile) stream otomatik olarak kapatılır.
    try (BufferedReader reader = new BufferedReader(new FileReader(path))) {
        String line = reader.readLine();
        // işlemler...
    } catch (IOException e) {
        logger.error("Dosya okuma hatası: {}", path);
        // Hata yönetimi...
    }
}

```

**5. Null Pointer Dereference (Null Kontrolü)**

A10 altındaki en yaygın CWE'lerden (CWE-476) biridir. Beklenmedik bir null değeri uygulamanın beklenmedik şekilde çökmesine neden olur.

```java

public void processUser(User user) {
    // Java 8+ Optional kullanımı ile beklenmedik çökmeleri engelleyin
    Optional.ofNullable(user)
            .map(User::getProfile)
            .ifPresentOrElse(
                profile -> logger.info("Profil bulundu: " + profile.getId()),
                () -> logger.warn("Profil bulunamadı, güvenli işlem başlatılıyor.")
            );
}

```

#### A10 İçin Genel Checklist

**Hata Politikası:** Uygulamanın her katmanında (Controller, Service, DB) hataların nasıl yakalanacağını standartlaştırın.

**Log Temizliği:** Hata loglarına asla kullanıcı şifresi, kredi kartı veya API anahtarı gibi verileri düşürmeyin.

**Default Deny:** Güvenlik kontrollerinde her zaman "önce reddet, sonra izin ver" mantığını tasarım seviyesinde (A06 ile bağlantılı) uygulayın.

**Resilience:** Dış servislere bağımlılıklarda Circuit Breaker (Resilience4j gibi) kullanarak, servis çöktüğünde uygulamanın ana akışının bozulmamasını sağlayın.
