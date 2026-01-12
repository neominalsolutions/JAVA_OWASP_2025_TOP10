### Yazılım Tedarik Zinciri ve Bütünlük Hataları

Bu risk, modern yazılımların %80-90'ının üçüncü parti kütüphanelerden oluştuğu gerçeğine dayanır. Eğer tedarik zincirindeki bir halka (bir kütüphane, bir CI/CD aracı veya bir güncelleme sunucusu) bozulursa, tüm sisteminiz tehlikeye girer.

### Temel Risk Belirtileri:

**Doğrulanmamış Kütüphaneler**
Maven Central, NPM veya PyPI gibi depolardan rastgele kütüphane çekilmesi.

**Güvensiz Deserialization:**
Dışarıdan gelen serileştirilmiş verinin (JSON, XML) içeriğinin kontrol edilmeden sisteme kabul edilmesi.

**CI/CD Zafiyetleri:**
Kodun üretim hattında (pipeline) yetkisiz bir şekilde değiştirilmesi.

**Dijital İmza Eksikliği:**
Güncellemelerin veya kod paketlerinin gerçekten iddia edilen kaynaktan gelip gelmediğinin doğrulanmaması.

### Net Uygulamalarında Önlemler ve Kod Örnekleri

**1. Güvensiz Deserialization (Seri Durumdan Çıkarma) Koruması**
Saldırgan, nesne içine gömülü zararlı kodlar göndererek sisteminizde komut çalıştırabilir (RCE).

```csharp

// Güvenilmeyen bir kaynaktan gelen veriyi doğrudan nesneye çevirmek tehlikelidir
// TEHLİKELİ: BinaryFormatter kullanımı.
// Saldırgan, stream içine sistem komutu çalıştıran bir nesne gömebilir.
BinaryFormatter formatter = new BinaryFormatter();
var myObj = (MyObject)formatter.Deserialize(inputStream);

// Güvenli Yaklaşım (Allow-list Kullanımı): System.Text.Json veya Newtonsoft.Json kullanımı
using System.Text.Json;
// 1. Veriyi tip güvenli bir şekilde karşıla
string jsonString = await new StreamReader(inputStream).ReadToEndAsync();
// 2. Sadece belirttiğiniz sınıfa (MyObject) dönüşüm yapar.
// Dışarıdan gelen "beklenmedik" sınıflar asla çalıştırılmaz.
MyObject? obj = JsonSerializer.Deserialize<MyObject>(jsonString);

```

**2. Bağımlılık (Dependency) Güvenliği ve Checksum Doğrulama**

.NET Core tarafında, bağımlılıkların değişmediğini (checksum/hash doğrulama) garanti altına almanın ve tedarik zinciri saldırılarını önlemenin en net ve yerleşik (native) çözümü NuGet Lock Files (Kilit Dosyaları) kullanmaktır.

1. Adım csproj dosyasına aşağıdaki tanımlamayı ekle

```xml

<PropertyGroup>
  <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>

  <RestoreLockedMode Condition="'$(ContinuousIntegrationBuild)' == 'true'">true</RestoreLockedMode>
</PropertyGroup>

```

2. Adım

```bash

dotnet restore

```

3. Adım: CI/CD Pipeline'da Doğrulama : Pipeline (GitHub Actions, Azure DevOps vb.) üzerinde kodunuzu derlerken şu komutu kullanın:

```bash
dotnet restore --locked-mode
```

Ayrıca kullanılan paketlerin bilinen bir açığı (CVE) olup olmadığını şu komutla tarayalım.

```bash
dotnet list package --vulnerable --include-transitive
```

**3. Veri Bütünlüğünü Dijital İmza ile Doğrulama**

Eğer uygulamanız dışarıdan bir dosya veya konfigürasyon alıyorsa, bu dosyanın yolda değiştirilmediğini dijital imzalarla (HMAC veya RSA) doğrulamalısınız.

```csharp

using System.Security.Cryptography;

public bool VerifyDataIntegrity(byte[] data, byte[] signature, RSA rsaPublicKey)
{
    // NET: HashAlgorithmName.SHA256 + RSASignaturePadding.Pkcs1

    return rsaPublicKey.VerifyData(
        data,
        signature,
        HashAlgorithmName.SHA256,
        RSASignaturePadding.Pkcs1
    );
}

```

**4. Kurumsal Strateji: SBOM (Yazılım Malzeme Listesi)**
A03 riskini yönetmenin en etkili yolu bir SBOM (Software Bill of Materials) oluşturmaktır. Bu, uygulamanızın kullandığı her bir parçanın (kütüphane, versiyon, lisans) listesidir.

**CycloneDX .NET CLI** formatında **SBOM** raporları üretin.

```bash

dotnet tool install --global CycloneDX
dotnet CycloneDX MyProject.sln -o ./sbom-output -f json

```

**OWASP Dependency-Check** gibi araçları pipeline'ınıza ekleyerek, bilinen bir zafiyeti olan kütüphaneyi daha build aşamasında engelleyin.

**Not:** Yazılım bütünlüğü sadece kodla değil, sürecin tamamıyla ilgilidir. GitHub aksiyonlarınızdan, kullandığınız Docker imajlarına kadar her şeyin kaynağını doğrulamalısınız.

```yml
name: 'Security Supply Chain Scan (.NET Core)'

on:
  push:
    branches: ['main', 'develop']
  pull_request:
    branches: ['main']
  schedule:
    - cron: '0 0 * * 1' # Her Pazartesi (Haftalık zafiyet taraması)

jobs:
  depcheck:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Setup .NET SDK
        uses: actions/setup-dotnet@v4
        with:
          dotnet-version: '8.0.x' # Projenize uygun versiyon (LTS)

      - name: Restore Dependencies
        run: dotnet restore # .NET'te bağımlılık ağacının (project.assets.json) oluşması için şart.

      # OPSİYONEL: .NET'in yerleşik zafiyet taraması (Hızlı ve etkili)
      - name: .NET Native Vulnerability Scan
        run: dotnet list package --vulnerable --include-transitive

      - name: OWASP Dependency-Check Scan
        uses: dependency-check/Dependency-Check_Action@main
        id: DepCheck
        with:
          project: 'Neominal-DotNet-Service'
          path: '.'
          format: 'HTML'
          # CVSS skoru 7.0 (High) ve üzeri ise pipeline'ı kır (fail)
          args: >
            --failBuildOnCVSS 7
            --enableRetired
            --suppression suppression.xml
            --scan "**/*.csproj"
            --scan "**/project.assets.json"
        # SBOM'u manuel oluşturmak yerine her "build" sürecinde otomatik üretmek en doğrusudur. Supply Chain Security hattına şu adımı ekleyebilirsin:
      - name: Generate SBOM
        run: |
          dotnet tool install --global CycloneDX
          dotnet CycloneDX MyProject.csproj -o ./artifacts -f json

      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: project-sbom
          path: ./artifacts/bom.json

      - name: Upload Scan Report
        uses: actions/upload-artifact@v4
        if: always() # Hata olsa da olmasa da raporu sakla
        with:
          name: dependency-check-report
          path: 'reports/dependency-check-report.html'
```
