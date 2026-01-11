#### A09:2025 - Güvenlik Günlüğü ve Uyarı Hataları

Bu zafiyet, saldırıları tespit etme, müdahale etme ve adli analiz yapma yeteneğinin olmamasıdır. Çoğu veri ihlalinde, saldırganların sistemde fark edilmeden ortalama 200 günden fazla kaldığı görülmektedir.

#### Temel Risk Belirtileri:

**Görünmezlik** Başarısız girişler, yetki aşımı denemeleri ve girdi doğrulama hatalarının loglanmaması.

**Yetersiz İçerik:** Logların kim, ne zaman, nerede ve hangi işlem sorularına cevap vermemesi.

**Lokal Depolama:** Logların sadece sunucu içinde tutulması (Saldırgan içeri girdiğinde ilk iş logları siler).

**Uyarı Eksikliği:** Kritik bir güvenlik olayı olduğunda kimseye bildirim gitmemesi.

### Java Uygulamalarında Önlemler ve Kod Örnekleri

**1. MDC (Mapped Diagnostic Context) ile İzlenebilirlik**

Sadece "Hata oluştu" yazmak yetmez. O hatayı hangi kullanıcı, hangi istek (Trace ID) ile yaptı? MDC, bu veriyi tüm log satırlarına otomatik ekler.

**Örnek:** Log Filter/Interceptor

```java


@Component
public class SecurityLoggingFilter implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String userId = httpRequest.getUserPrincipal() != null ? httpRequest.getUserPrincipal().getName() : "ANONYMOUS";
        String traceId = UUID.randomUUID().toString();

        try {
            MDC.put("userId", userId);
            MDC.put("traceId", traceId);
            MDC.put("clientIp", httpRequest.getRemoteAddr());
            chain.doFilter(request, response);
        } finally {
            MDC.clear(); // Bellek sızıntısını önlemek için mutlaka temizle
        }
    }
}

```

**2. Spring Security Audit Events (Denetim Günlükleri)**
Başarılı/başarısız login denemelerini manuel loglamak yerine Spring'in yerleşik AbstractAuthenticationAuditListener yapısını kullanmalısın.

```java

@Component
public class SecurityAuditEventListener {

    private static final Logger logger = LoggerFactory.getLogger(SecurityAuditEventListener.class);

    @EventListener
    public void onFailure(AuthenticationFailureBadCredentialsEvent event) {
        // Saldırganın denediği kullanıcı adını ve kaynağı logla
        logger.warn("SECURITY_EVENT: Başarısız giriş denemesi. Kullanıcı: {} - Kaynak: {}",
                event.getAuthentication().getName(),
                event.getAuthentication().getDetails());
    }

    @EventListener
    public void onAuthorizationFailure(AuthorizationFailureEvent event) {
        // Yetkisi olmayan bir endpoint'e erişim denemesi
        logger.error("SECURITY_EVENT: Yetkisiz erişim reddedildi! Kullanıcı: {} - Kaynak: {}",
                event.getAuthentication().getName(),
                event.getExpression());
    }
}

```

**3. Yapılandırılmış Loglama (JSON Format)**
Modern log analiz araçları (ELK, Splunk, Graylog) düz metin yerine JSON formatını tercih eder. Bu, loglar üzerinde kolayca sorgu (Örn: "Son 1 saatte 50'den fazla başarısız login olan IP'leri getir") yapmanı sağlar.

**logback-spring.xml (Logstash Encoder):**

```xml

<appender name="logstash" class="net.logstash.logback.appender.LogstashTcpSocketAppender">
    <destination>127.0.0.1:4560</destination>
    <encoder class="net.logstash.logback.encoder.LogstashEncoder">
        <includeMdc>true</includeMdc>
        <customFields>{"app_name":"ABC-Service"}</customFields>
    </encoder>
</appender>

```

#### Alerting (Uyarı) Stratejisi

**Kritik Hatalar (5xx)** Anlık Bildirim **Slack / Teams**
**Brute Force Belirtisi** IP Engelleme / Alert **Sentinel / Fail2Ban**
**Anormal Veri Çıkışı** Dashboard + Email **Grafana / Prometheus**
**Admin İşlemleri** Audit Trail (Silinemez Log) **AWS CloudWatch / Azure Monitor**

**Tavsiye:**

Sisteminin "uyarı" mekanizmasını test etmek için bir "Game Day" düzenle. Bir ekip arkadaşın sisteme kasıtlı olarak hatalı girişler yapsın veya yetkisiz sayfalara erişmeye çalışsın. Eğer 5 dakika içinde senin telefonuna veya Slack kanalına bir uyarı düşmüyorsa, A09 zafiyetine sahipsin demektir.
