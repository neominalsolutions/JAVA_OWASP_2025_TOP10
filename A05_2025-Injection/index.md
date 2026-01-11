### A05:2025 - Injection

Injection, kullanıcıdan gelen kontrol edilmemiş verinin bir komut veya sorgu içine "süzülmeden" dahil edilmesiyle oluşur. Uygulama, bu veriyi kodun bir parçası sanarak çalıştırır.

#### Temel Risk Belirtileri:

**SQL Injection:** Kullanıcı girişinin SQL sorgularına doğrudan eklenmesi.

**Komut (OS) Injection:** Uygulamanın işletim sistemi komutlarını dışarıdan gelen parametrelerle çalıştırması.

**Object-Graph Navigation Language (OGNL) / Expression Language (EL) Injection:** Özellikle eski Spring ve Struts uygulamalarında görülen, dinamik kod çalıştırma zafiyetleri.

**Log Injection:** Loglara yazılan verinin manipüle edilerek izleme araçlarının (Splunk, ELK vb.) yanıltılması.

#### Java Uygulamalarında Önlemler ve Kod Örnekleri

**1. SQL Injection:** Dinamik Sorgu Yerine Parametrik Sorgu

Spring Data JPA kullanıyor olsan bile @Query içinde "Native Query" yazarken hata yapma payımız yüksektir.

```java

// String concatenation (birleştirme) asla yapma!
@Query(value = "SELECT * FROM users WHERE username = '" + username + "'", nativeQuery = true)
User findByInsecureUsername(String username);

// Doğru
// Spring Data JPA parametreleri otomatik olarak güvenli hale getirir (PreparedStatement)
@Query(value = "SELECT * FROM users WHERE username = :username", nativeQuery = true)
User findBySecureUsername(@Param("username") String username);


// Not: Eğer CriteriaBuilder veya EntityManager kullanıyorsan, mutlaka .setParameter() metodunu kullanmalısın.

```

**2. OS Command Injection:** Komut Çalıştırmadan Kaçınmak

İşletim sistemi seviyesinde komut çalıştırmak (Örn: Runtime.getRuntime().exec()) çok risklidir. Eğer mutlaka gerekiyorsa, kullanıcıdan gelen veriyi asla doğrudan içeri alma.

```java

// Hatalı
// Kullanıcı "file.txt; rm -rf /" yazarsa sistem biter.
String command = "ls -l " + userInput;
Runtime.getRuntime().exec(command);

// DOĞRU (Allow-list ve ProcessBuilder):
public void executeListCommand(String fileName) throws IOException {
    // Sadece izin verilen karakterleri kabul et (Regex ile validation)
    if (!fileName.matches("^[a-zA-Z0-9._-]+$")) {
        throw new SecurityException("Geçersiz dosya adı!");
    }

    // Parametreleri ayrı ayrı vererek shell interpretasyonunu engelle
    ProcessBuilder pb = new ProcessBuilder("ls", "-l", fileName);
    pb.start();
}

```

**3. Log Injection:** Log Dosyalarını Koruma:

Saldırgan, loglara \r\n (yeni satır) karakterleri ekleyerek log kayıtlarını sahteleyebilir veya Log4j zafiyetinde (Log4Shell) olduğu gibi kod çalıştırabilir.

```java

// HATALI:

// Kullanıcı adı olarak "admin \n ERROR: Login failed" girerse log bozulur
logger.info("User login attempt: " + username);

// Güvenli

public String sanitizeForLog(String input) {
    return input.replaceAll("[\r\n]", "_");
}


```

#### INPUT Sanitization için aşağıdaki kütüphaneler güvenlidir.

**1. HTML/XSS Temizleme (Altın Standart):** OWASP Java HTML Sanitizer

- Maven: com.googlecode.owasp-java-html-sanitizer:owasp-java-html-sanitizer:20260102.1

```java

import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;

public class SecurityUtils {
    // Sadece kalın yazı, italik ve linklere izin veren bir politika
    private static final PolicyFactory POLICY = Sanitizers.FORMATTING.and(Sanitizers.LINKS);

    public static String sanitizeHtml(String untrustedHtml) {
        return POLICY.sanitize(untrustedHtml);
    }
}

```

**2. Genel Kodlama (Encoding):** OWASP Java Encoder:
Veriyi temizlemek yerine (karakterleri silmek), veriyi zararsız hale getirmek (kodlamak) çoğu zaman daha güvenlidir.

```java

import org.owasp.encoder.Encode;

// HTML içinde bir veriyi güvenli basmak için:
String safeHtml = Encode.forHtml(userInput);

// JavaScript içinde bir değişkeni güvenli basmak için:
String safeJs = Encode.forJavaScript(userInput);

```

**3. Modern/Deklaratif Yaklaşım:** Sanitizer-Lib

Eğer Spring Boot kullanıyorsanız, DTO seviyesinde anotasyonlarla temizlik yapmak için sanitizer-lib gibi modern kütüphaneler kod okunabilirliğini artırır.

- Javada Güvenli Loglama için;

**Framework:** SLF4J (Interface) + Logback (Spring Boot default) veya Log4j2 (Performans için).
**Maskeleme:** Hassas verileri (kredi kartı, şifre) loglara yazmadan önce maskeleyin.
**Logları** düz metin yerine JSON formatında basın (Logstash Encoder). Bu, Log Injection saldırılarını yapısal olarak engeller.

Log Injection'ı engellemek için replace fonksiyonu kullanılabilir.

#### logback-spring.xml yapılandırması:

```xml

<configuration>
    <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
        <encoder>
            <pattern>
                %d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %replace(%replace(%msg){'[\r\n]', ''}){'password=.*', 'password=****'}%n
            </pattern>
        </encoder>
    </appender>
    <root level="info">
        <appender-ref ref="STDOUT" />
    </root>
</configuration>

```

#### Injection Engellemek İçin Tavsiyeler

**Input Validation:** Gelen her veriyi (isName, isEmail, isNumeric) sıkı bir şekilde doğrula.
**Safe API:** PreparedStatement, Stored Procedures veya güvenli ORM araçlarını tercih et.
**Least Privilege:** Veritabanı kullanıcısının sadece ihtiyacı olan yetkilere (SELECT, INSERT) sahip olmasını sağla (DROP yetkisi olmasın).
**Avoid Native Queries:** Mümkünse JPQL veya HQL kullan, Native SQL'e sadece mecbur kaldığında ve parametrik olarak başvur.
