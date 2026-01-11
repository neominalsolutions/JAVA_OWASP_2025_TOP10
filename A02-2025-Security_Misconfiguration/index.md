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

### Java Uygulamalarında Önlemler ve Kod Örnekleri

**1. Hata Mesajlarını Gizleme (Stack Trace Koruması)**
Uygulamanız çöktüğünde kullanıcıya asla kod yapısını ifşa eden mesajlar göstermemelisiniz. Spring Boot'ta ControllerAdvice kullanarak bunu yönetebilirsiniz.

```java

@ControllerAdvice
public class GlobalExceptionHandler {

    // Yakalanmayan tüm hatalar için genel, güvenli bir mesaj döndürür
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Object> handleAllExceptions(Exception ex) {
        // Loglara detaylı hatayı yaz ama kullanıcıya sadece ID ve mesaj ver
        // Logger.error("Error occurred: ", ex);

        Map<String, Object> body = new HashMap<>();
        body.put("timestamp", LocalDateTime.now());
        body.put("message", "Bir sistem hatası oluştu. Lütfen destekle iletişime geçin.");

        return new ResponseEntity<>(body, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}

```

```app.properties

server.error.include-stacktrace=never
server.error.include-message=never

```

---

**2. Güvenli HTTP Başlıklarını (Security Headers) Yapılandırma**

Spring Security varsayılan olarak birçok başlığı ekler ancak bunları projenize göre sıkılaştırmanız gerekir.

```java


@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .headers(headers -> headers
                // Clickjacking koruması
                .frameOptions(frameOptions -> frameOptions.deny())
                // HSTS (HTTPS zorunluluğu)
                .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31536000))
                // Content Security Policy (CSP)
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives("default-src 'self'; script-src 'self' https://trusted.com;"))
            );
        return http.build();
    }
}

```

**3. XML ve JSON İşleyicilerini Güvenli Hale Getirme (XXE Önleme)**
Eski Java sürümlerinde XML parser'lar dış varlıkları (External Entities) yüklemeye açıktır. Bu, Security Misconfiguration'ın klasik bir örneğidir.

```java

public void secureXmlParsing(String xmlInput) throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

    // XXE (XML External Entity) saldırılarını engellemek için özellikler
    String FEATURE = "http://apache.org/xml/features/disallow-doctype-decl";
    dbf.setFeature(FEATURE, true);
    dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
    dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

    DocumentBuilder builder = dbf.newDocumentBuilder();
    // ... işlemler
}

```

**4. Hassas Verilerin Yapılandırma Dosyalarında Saklanmaması**

Şifreleri veya API anahtarlarını application.properties içinde düz metin olarak saklamak büyük bir hatadır. Bunun yerine ortam değişkenleri (Environment Variables) veya Vault gibi araçlar kullanılmalıdır.

```bash


# YANLIŞ:
spring.datasource.password=123456

# DOĞRU (Ortam değişkeninden oku): Küçük Projeler İçin: İşletim sistemi üzerinden Environment Variables kullanabiliriz.
spring.datasource.password=${DB_PASSWORD}


# Spring Cloud Vault -> Büyük/Cloud Projeler İçin: Vault, AWS Secrets Manager veya Azure Key Vault entegrasyonu kullanın.

spring:
  cloud:
    vault:
      uri: https://vault.firma.com:8200
      token: ${VAULT_TOKEN}
      kv:
        enabled: true
        backend: secret
        default-context: uygulama-adı

```

```java

@ConfigurationProperties("my.app.config")
@Data
public class AppConfig {
    private String apiKey; // Vault'ta 'my.app.config.apiKey' olarak saklanır
}

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
