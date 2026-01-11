### Yazılım Tedarik Zinciri ve Bütünlük Hataları

Bu risk, modern yazılımların %80-90'ının üçüncü parti kütüphanelerden oluştuğu gerçeğine dayanır. Eğer tedarik zincirindeki bir halka (bir kütüphane, bir CI/CD aracı veya bir güncelleme sunucusu) bozulursa, tüm sisteminiz tehlikeye girer.

### Temel Risk Belirtileri:

**Doğrulanmamış Kütüphaneler**
Maven Central, NPM veya PyPI gibi depolardan rastgele kütüphane çekilmesi.

**Güvensiz Deserialization:**
Dışarıdan gelen serileştirilmiş verinin (JSON, XML, Java Object) içeriğinin kontrol edilmeden sisteme kabul edilmesi.

**CI/CD Zafiyetleri:**
Kodun üretim hattında (pipeline) yetkisiz bir şekilde değiştirilmesi.

**Dijital İmza Eksikliği:**
Güncellemelerin veya kod paketlerinin gerçekten iddia edilen kaynaktan gelip gelmediğinin doğrulanmaması.

### Java Uygulamalarında Önlemler ve Kod Örnekleri

**1. Güvensiz Deserialization (Seri Durumdan Çıkarma) Koruması**
Bütünlük hatalarının en yaygın Java örneğidir. Saldırgan, nesne içine gömülü zararlı kodlar göndererek sisteminizde komut çalıştırabilir (RCE).

```java

// Güvenilmeyen bir kaynaktan gelen veriyi doğrudan nesneye çevirmek tehlikelidir
ObjectInputStream ois = new ObjectInputStream(inputStream);
MyObject obj = (MyObject) ois.readObject(); // Saldırgan burada kod çalıştırabilir!

// Güvenli Yaklaşım (Allow-list Kullanımı): Java 9+ ile gelen ObjectInputFilter kullanarak sadece izin verdiğiniz sınıfların deserialization işlemine girmesini sağlamalısınız.

ObjectInputStream ois = new ObjectInputStream(inputStream);

// Sadece MyObject sınıfına izin ver, diğer her şeyi reddet
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter("com.abc.models.MyObject;!*");
ois.setInternalObjectInputFilter(filter);

MyObject obj = (MyObject) ois.readObject();

```

**2. Bağımlılık (Dependency) Güvenliği ve Checksum Doğrulama**

Tedarik zinciri saldırılarını önlemek için kullandığınız kütüphanelerin "hash" değerlerini (checksum) kontrol etmelisiniz. Maven'da bu iş için maven-enforcer-plugin kullanılabilir.

```xml

<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-enforcer-plugin</artifactId>
    <version>3.4.1</version>
    <executions>
        <execution>
            <id>enforce-banned-dependencies</id>
            <goals>
                <goal>enforce</goal>
            </goals>
            <configuration>
                <rules>
                    <bannedDependencies>
                        <excludes>
                            <exclude>log4j:log4j:[1.2.17]</exclude>
                            <exclude>commons-collections:commons-collections:[3.2.1]</exclude>
                        </excludes>
                    </bannedDependencies>
                </rules>
            </configuration>
        </execution>
    </executions>
</plugin>

```

**3. Veri Bütünlüğünü Dijital İmza ile Doğrulama**

Eğer uygulamanız dışarıdan bir dosya veya konfigürasyon alıyorsa, bu dosyanın yolda değiştirilmediğini dijital imzalarla (HMAC veya RSA) doğrulamalısınız.

```java

public boolean verifyDataIntegrity(byte[] data, byte[] signature, PublicKey publicKey) throws Exception {
    Signature sig = Signature.getInstance("SHA256withRSA");
    sig.initVerify(publicKey);
    sig.update(data);

    // Veri ile imza eşleşiyor mu?
    return sig.verify(signature);
}

```

**4. Kurumsal Strateji: SBOM (Yazılım Malzeme Listesi)**
A03 riskini yönetmenin en etkili yolu bir SBOM (Software Bill of Materials) oluşturmaktır. Bu, uygulamanızın kullandığı her bir parçanın (kütüphane, versiyon, lisans) listesidir.

**CycloneDX** veya **SPDX** formatında **SBOM** raporları üretin.

**OWASP Dependency-Check** gibi araçları pipeline'ınıza ekleyerek, bilinen bir zafiyeti olan kütüphaneyi daha build aşamasında engelleyin.

**Not:** Yazılım bütünlüğü sadece kodla değil, sürecin tamamıyla ilgilidir. GitHub aksiyonlarınızdan, kullandığınız Docker imajlarına kadar her şeyin kaynağını doğrulamalısınız.

```yml
name: 'Security Supply Chain Scan'

on:
  push:
    branches: ['main', 'develop']
  pull_request:
    branches: ['main']
  schedule:
    - cron: '0 0 * * 1' # Her Pazartesi otomatik tara (yeni çıkan zafiyetler için), Saldırganlar her gün yeni açıklar bulur. Kodunuz değişmese bile, kullandığınız kütüphane için bugün yeni bir zafiyet duyurulmuş olabilir. Bu yüzden haftalık tarama kritiktir.

jobs:
  depcheck:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up JDK 21 # Projenize uygun versiyon
        uses: actions/setup-java@v4
        with:
          java-version: '21'
          distribution: 'temurin'
          cache: 'maven'

      - name: OWASP Dependency-Check Scan
        uses: dependency-check/Dependency-Check_Action@main
        id: DepCheck
        with:
          project: 'ABC-Service'
          path: '.'
          format: 'HTML'
          # CVSS skoru 7.0 ve üzeri (Yüksek/Kritik) ise build'i başarısız say
          args: >
            --failBuildOnCVSS 7
            --enableRetired
            --suppression suppression.xml
        # failBuildOnCVSS 7: Bu en önemli parametredir. Eğer projenizde kullanılan bir kütüphanede 7.0 (High) veya üzeri bir zafiyet bulunursa, pipeline "fail" olur ve kodun production'a gitmesini engeller.
        # suppression.xml: Bazen "False Positive" (yanlış alarm) durumları olur veya bazı riskleri bilinçli olarak kabul edersiniz. Bu dosya ile o spesifik uyarıları susturabilirsiniz

      - name: Upload Scan Report
        uses: actions/upload-artifact@v4 # Tarama sonucunda oluşan detaylı HTML raporunu indirip hangi kütüphanenin hangi CVE koduyla sorunlu olduğunu görebilirsiniz.
        if: always() # Tarama başarısız olsa bile raporu kaydet
        with:
          name: dependency-check-report
          path: 'reports/dependency-check-report.html'
```
