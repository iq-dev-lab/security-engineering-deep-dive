# SSRF — 서버를 통해 내부망을 공격하는 방법

---

## 🎯 핵심 질문

- **SSRF 취약점이란 무엇인가?** 공격자가 지정한 URL을 서버가 대신 요청하도록 강제할 수 있는 취약점입니다.
- **왜 클라우드 메타데이터 서비스가 표적이 되는가?** AWS, GCP, Azure의 로컬 IP 메타데이터 엔드포인트에서 IAM 자격증명을 획득할 수 있기 때문입니다.
- **URL 화이트리스트 구현만으로 충분한가?** 아니요. SSRF 우회 기법(IP 스푸핑, 리다이렉션)을 고려해야 합니다.
- **IMDSv2는 어떻게 SSRF를 방어하는가?** PUT 메서드로 토큰을 먼저 요청받아야 하므로, GET-only SSRF 공격이 실패합니다.

---

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

### Capital One 사건 (2019)
**배경**: 웹 애플리케이션의 부하 분산 장치(ALB) 설정 오류로 SSRF 취약점이 존재했습니다.

**공격 흐름**:
```
공격자 → ALB(로드밸런서) → 내부 서버 → AWS 메타데이터 서비스(169.254.169.254)
↓
IAM 자격증명 획득
↓
S3 버킷, RDS 데이터베이스, Lambda 함수 전체 접근
↓
1.6억 개의 개인정보 유출
```

**결과**: 약 7억 달러의 합의금 및 규제 강화

---

## 😱 취약한 코드/설정 (Before — 원리를 모를 때의 구현)

### 취약한 Spring Controller (사용자 URL 검증 없음)

```java
@RestController
@RequestMapping("/api/proxy")
public class ProxyController {

    @Autowired
    private RestTemplate restTemplate;

    // ❌ 위험: 사용자 입력값을 직접 요청 URL로 사용
    @GetMapping("/fetch")
    public String fetchContent(@RequestParam String url) {
        try {
            ResponseEntity<String> response = restTemplate.getForEntity(url, String.class);
            return response.getBody();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // ❌ 위험: 리다이렉션을 따라감 (공격자가 http://trusted.com → http://169.254.169.254 리다이렉션)
    @PostMapping("/fetch-json")
    public ResponseEntity<String> fetchJson(@RequestBody Map<String, String> request) {
        String url = request.get("url");
        return restTemplate.postForEntity(url, null, String.class);
    }
}
```

### 취약한 URL 다운로더 (Java)

```java
public class ImageDownloader {

    // ❌ 위험: 내부 IP 범위 확인 없음
    public byte[] downloadImage(String imageUrl) throws Exception {
        URL url = new URL(imageUrl);
        URLConnection connection = url.openConnection();
        
        // connection.setConnectTimeout(5000); 타임아웃만으로는 부족
        
        InputStream inputStream = connection.getInputStream();
        return inputStream.readAllBytes();
    }
}
```

### 취약한 설정 (AWS IMDSv1 사용)

```yaml
# ❌ 위험한 AWS 환경 설정
ec2:
  iam_role_arn: arn:aws:iam::123456789:role/app-role
  # IMDSv1은 GET 단일 요청으로 자격증명 획득 가능
  imds_version: "v1"  # 또는 설정 생략
```

---

## ✨ 방어 코드/설정 (After — 공격 원리를 알고 설계한 구현)

### 방어 1: URL 검증 + 내부 IP 차단

```java
@RestController
@RequestMapping("/api/proxy")
public class SecureProxyController {

    @Autowired
    private RestTemplate restTemplate;

    // 허용 도메인 목록
    private static final Set<String> ALLOWED_DOMAINS = Set.of(
        "api.example.com",
        "cdn.example.com",
        "public-data.service.com"
    );

    // RFC1918 내부 IP 범위 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    private static final List<IPAddressRange> BLOCKED_RANGES = Arrays.asList(
        IPAddressRange.valueOf("10.0.0.0/8"),
        IPAddressRange.valueOf("172.16.0.0/12"),
        IPAddressRange.valueOf("192.168.0.0/16"),
        IPAddressRange.valueOf("127.0.0.0/8"),    // localhost
        IPAddressRange.valueOf("169.254.0.0/16")  // AWS 메타데이터
    );

    @GetMapping("/fetch")
    public String fetchContent(@RequestParam String url) throws MalformedURLException {
        // 1단계: 형식 검증
        URL parsedUrl = new URL(url);
        
        // 2단계: 프로토콜 검증 (http/https만 허용)
        if (!parsedUrl.getProtocol().matches("https?")) {
            throw new SecurityException("Only HTTP(S) protocols are allowed");
        }

        // 3단계: 호스트명 검증 (화이트리스트)
        String host = parsedUrl.getHost();
        if (!ALLOWED_DOMAINS.contains(host)) {
            throw new SecurityException("Domain not in whitelist: " + host);
        }

        // 4단계: IP 주소 직접 접근 차단 및 내부 IP 범위 확인
        try {
            InetAddress inetAddress = InetAddress.getByName(host);
            String ipAddress = inetAddress.getHostAddress();
            
            for (IPAddressRange range : BLOCKED_RANGES) {
                if (range.contains(IPAddress.parse(ipAddress))) {
                    throw new SecurityException("Internal IP address not allowed: " + ipAddress);
                }
            }
        } catch (UnknownHostException e) {
            throw new SecurityException("Cannot resolve hostname: " + host);
        }

        // 5단계: 포트 범위 검증 (고위험 포트 차단)
        int port = parsedUrl.getPort();
        if (isRestrictedPort(port)) {
            throw new SecurityException("Restricted port: " + port);
        }

        // 6단계: 리다이렉션 따라가기 비활성화
        RestTemplate safeRestTemplate = createRestTemplateWithoutRedirects();
        
        try {
            ResponseEntity<String> response = safeRestTemplate.getForEntity(url, String.class);
            return response.getBody();
        } catch (Exception e) {
            throw new SecurityException("Failed to fetch URL: " + e.getMessage());
        }
    }

    private boolean isRestrictedPort(int port) {
        // 메타데이터 서비스, SSH, SMTP 등 고위험 포트 차단
        return port == 22 || port == 23 || port == 25 || 
               port == 119 || port == 135 || port == 139 || 
               port == 445 || port == 3306 || port == 5432 || 
               port == 27017; // MongoDB
    }

    private RestTemplate createRestTemplateWithoutRedirects() {
        HttpClientBuilder httpClientBuilder = HttpClientBuilder.create()
            .disableRedirectHandling()
            .setConnectionManager(new PoolingHttpClientConnectionManager())
            .setConnectionTimeToLive(30, TimeUnit.SECONDS);

        HttpClient httpClient = httpClientBuilder.build();
        HttpComponentsClientHttpRequestFactory factory = 
            new HttpComponentsClientHttpRequestFactory(httpClient);
        
        factory.setConnectTimeout(5000);  // 5초 타임아웃
        factory.setReadTimeout(5000);
        
        return new RestTemplate(factory);
    }
}
```

**의존성 추가** (build.gradle):
```gradle
dependencies {
    implementation 'org.apache.httpcomponents:httpclient:4.5.14'
    implementation 'org.apache.commons:commons-ipmath:1.32'
}
```

### 방어 2: Spring WebClient (Reactive) 사용

```java
@Component
public class SecureWebClientFetcher {

    private final WebClient webClient;
    private static final Set<String> ALLOWED_DOMAINS = Set.of(
        "api.example.com",
        "cdn.example.com"
    );

    public SecureWebClientFetcher() {
        // 리다이렉션 비활성화 + 타임아웃 설정
        this.webClient = WebClient.builder()
            .clientConnector(new ReactorClientHttpConnector(
                HttpClient.create()
                    .responseTimeout(Duration.ofSeconds(10))
                    .followRedirect(false)  // ⭐ 리다이렉션 따라가지 않음
            ))
            .build();
    }

    public Mono<String> fetchContent(String url) {
        try {
            URL parsedUrl = new URL(url);
            validateUrl(parsedUrl);
            
            return webClient.get()
                .uri(url)
                .header("User-Agent", "SecureBot/1.0")
                .retrieve()
                .bodyToMono(String.class)
                .timeout(Duration.ofSeconds(10))
                .onErrorMap(e -> new SecurityException("Fetch failed: " + e.getMessage()));
                
        } catch (MalformedURLException e) {
            return Mono.error(new SecurityException("Invalid URL: " + e.getMessage()));
        }
    }

    private void validateUrl(URL url) {
        // 앞서 구현한 검증 로직 재사용
        if (!ALLOWED_DOMAINS.contains(url.getHost())) {
            throw new SecurityException("Domain not whitelisted");
        }
    }
}
```

### 방어 3: AWS IMDSv2 활성화

```yaml
# application.yml - AWS 환경 설정
aws:
  imds:
    version: "v2"  # ⭐ IMDSv2 필수
    token_ttl_seconds: 21600
```

**Java 코드 (Spring Cloud AWS 사용)**:
```java
@Configuration
public class AwsConfig {

    @Bean
    public AwsCredentialsProvider awsCredentialsProvider() {
        // IMDSv2를 통한 자격증명 자동 획득
        // Spring은 IMDSv2 요청(PUT + 토큰)을 자동으로 처리
        return DefaultCredentialsProvider.create();
    }
}
```

**EC2 사용자 데이터에서 IMDSv2 강제**:
```bash
#!/bin/bash
# IMDSv1 비활성화, IMDSv2만 허용
aws ec2 modify-instance-metadata-options \
    --instance-id $(ec2-metadata --instance-id | cut -d " " -f 2) \
    --http-endpoint enabled \
    --http-tokens required \  # ⭐ IMDSv2 필수
    --http-put-response-hop-limit 1
```

---

## 🔬 공격 원리 분석 (공격자 관점의 내부 동작)

### 기본 SSRF 공격 흐름

```
1. 공격자가 악의적 URL 입력
   ↓ POST /api/proxy/fetch?url=http://169.254.169.254/latest/meta-data/
   ↓
2. 서버가 유효성 검사 없이 HTTP 요청 실행
   ↓
3. 서버의 IP에서 출발한 요청이 내부 메타데이터 서비스로 도달
   ↓
4. 메타데이터 서비스는 localhost에서 온 요청을 신뢰 (방화벽 우회)
   ↓
5. 공격자가 IAM 자격증명, S3 버킷 목록, RDS 암호 등 획득
```

### IMDSv1 vs IMDSv2 공격 방식

**IMDSv1 (취약함)**:
```bash
# 단일 GET 요청으로 자격증명 획득 가능
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/app-role

# 응답:
{
  "Code": "Success",
  "LastUpdated": "2024-01-15T10:30:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "AKIA...",
  "SecretAccessKey": "wJal...",
  "Token": "IQoJb3Jp...",
  "Expiration": "2024-01-15T16:30:00Z"
}
```

**IMDSv2 (방어됨)**:
```bash
# 1단계: PUT 요청으로 토큰 획득 (SSRF로는 PUT 메서드 사용 어려움)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# 2단계: GET 요청 시 토큰 필수 (SSRF가 토큰 없으면 실패)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/app-role \
  -H "X-aws-ec2-metadata-token: $TOKEN"

# 토큰 없이 GET하면 401 Unauthorized
```

### URL 스푸핑 우회 기법

```java
// 공격자가 시도하는 우회 기법들:

// 1. IP 주소 직접 사용
String url1 = "http://169.254.169.254/";  // 직접 IP

// 2. 16진수 표현 (IP 파서 우회)
String url2 = "http://0xa9fee4fe/";  // 169.254.169.254를 16진수로

// 3. 8진수 표현
String url3 = "http://0251.0376.0251.0376/";

// 4. 정수형 표현
String url4 = "http://2852039166/";  // 169.254.169.254를 정수로

// 5. localhost 변형
String url5 = "http://127.0.0.1/";
String url6 = "http://localhost/";
String url7 = "http://0.0.0.0/";

// 6. DNS 리바인딩 (처음엔 허용된 호스트로 해석, 재요청 시 내부 IP로 변경)
String url8 = "http://dns-rebind.attacker.com/";
// DNS A 레코드가 처음에는 1.2.3.4(캐시 TTL 1초), 이후 169.254.169.254로 변경

// 7. URL 리다이렉션 체인
String url9 = "http://trusted.example.com/redirect?to=http://169.254.169.254/";
// trusted.example.com은 302 Location: http://169.254.169.254/ 반환
```

---

## 💻 실전 실험 (취약점 재현 → 공격 → 방어 검증)

### 실험 환경 구축

```bash
# 1. Docker Compose로 취약한 애플리케이션 시작
cat > docker-compose.yml << 'EOF'
version: '3.8'
services:
  vulnerable-app:
    build: .
    ports:
      - "8080:8080"
    environment:
      - JAVA_OPTS=-Xmx512m
    networks:
      - internal

  mock-metadata:
    image: python:3.11-slim
    ports:
      - "8169:8080"
    command: |
      python3 -c "
      from http.server import HTTPServer, BaseHTTPRequestHandler
      class MetadataHandler(BaseHTTPRequestHandler):
          def do_GET(self):
              if 'meta-data' in self.path:
                  self.send_response(200)
                  self.send_header('Content-Type', 'application/json')
                  self.end_headers()
                  self.wfile.write(b'{\"AccessKeyId\": \"AKIA_FAKE_KEY\", \"SecretAccessKey\": \"secret123\"}')
              else:
                  self.send_response(404)
                  self.end_headers()
          def log_message(self, format, *args):
              pass  # 로그 억제
      HTTPServer(('0.0.0.0', 8080), MetadataHandler).serve_forever()
      "
    networks:
      - internal

networks:
  internal:
    driver: bridge
EOF

docker-compose up -d
```

### 공격 시연 (취약한 버전)

```bash
# 취약한 엔드포인트 공격
curl -X GET "http://localhost:8080/api/proxy/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# 응답 (메타데이터 노출!)
# AccessKeyId: AKIA_FAKE_KEY, SecretAccessKey: secret123
```

### 방어 검증

```bash
# 방어된 엔드포인트 공격 (실패해야 함)
curl -X GET "http://localhost:8080/api/proxy/fetch?url=http://169.254.169.254/latest/meta-data/" \
  -H "X-API-Key: valid-token"

# 기대 응답:
# {"error": "Internal IP address not allowed: 169.254.169.254"}

# URL 스푸핑 시도
curl -X GET "http://localhost:8080/api/proxy/fetch?url=http://0xa9fee4fe/" \
  -H "X-API-Key: valid-token"

# 기대 응답:
# {"error": "Internal IP address not allowed: 169.254.169.254"}

# 허용된 도메인만 작동
curl -X GET "http://localhost:8080/api/proxy/fetch?url=https://api.example.com/data" \
  -H "X-API-Key: valid-token"

# 성공 응답
# {"data": "..."}
```

### 자동 테스트 (JUnit 5)

```java
@SpringBootTest
@AutoConfigureMockMvc
class SecureProxyControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void shouldBlockInternalIpAddresses() throws Exception {
        mockMvc.perform(get("/api/proxy/fetch")
            .param("url", "http://169.254.169.254/latest/meta-data/"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value(containsString("Internal IP")));
    }

    @Test
    void shouldBlockIpSpoofingAttempts() throws Exception {
        mockMvc.perform(get("/api/proxy/fetch")
            .param("url", "http://0xa9fee4fe/"))
            .andExpect(status().isBadRequest());
    }

    @Test
    void shouldAllowWhitelistedDomains() throws Exception {
        // mock 설정 필요
        mockMvc.perform(get("/api/proxy/fetch")
            .param("url", "https://api.example.com/data"))
            .andExpect(status().isOk());
    }

    @Test
    void shouldBlockRedirects() throws Exception {
        mockMvc.perform(get("/api/proxy/fetch")
            .param("url", "http://trusted.com/redirect-to-metadata"))
            .andExpect(status().isBadRequest());
    }
}
```

---

## 📊 공격 성공 조건 vs 방어 성공 조건 비교

| 조건 | 공격 성공 | 방어 성공 |
|------|---------|---------|
| **URL 검증** | 없음 또는 미흡 | URL 형식, 프로토콜, 호스트명 검증 |
| **IP 주소 해석** | 16진수/8진수/정수형 허용 | 모든 형식을 표준 IP로 정규화 후 차단 |
| **내부 IP 범위** | RFC1918 범위 접근 가능 | 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 차단 |
| **메타데이터 서비스** | 169.254.169.254 접근 가능 | 169.254.0.0/16 전체 차단 |
| **리다이렉션** | 302/301 따라감 | 리다이렉션 비활성화 |
| **고위험 포트** | 22, 3306, 5432 등 접근 | 제한된 포트만 허용 |
| **DNS 리바인딩** | 가능 | DNS 응답 재확인 또는 DNS 고정 |
| **IMDSv1** | 단일 GET 요청으로 자격증명 획득 | IMDSv2 강제 (PUT + 토큰) |

---

## ⚖️ 트레이드오프 (보안 강화 vs 사용성/성능)

| 방어 기법 | 보안 수준 | 성능 영향 | 구현 복잡도 |
|---------|----------|---------|----------|
| **화이트리스트 방식** | ⭐⭐⭐⭐⭐ (최고) | 거의 없음 | 낮음 |
| **리다이렉션 비활성화** | ⭐⭐⭐⭐⭐ | 없음 | 낮음 |
| **모든 IP 주소 재해석** | ⭐⭐⭐⭐ | 약간 (DNS 조회) | 중간 |
| **DNS 응답 재확인** | ⭐⭐⭐⭐⭐ | 중간 (재요청) | 높음 |
| **타임아웃 설정** | ⭐⭐ (부분적) | 있음 (지연) | 낮음 |

**권장**: 화이트리스트 + 내부 IP 차단 + 리다이렉션 비활성화 조합이 최적입니다.

---

## 📌 핵심 정리

1. **SSRF는 서버의 신뢰를 악용**: 공격자가 지정한 URL을 서버가 신뢰하고 요청함
2. **클라우드 메타데이터는 최우선 표적**: IAM 자격증명 → 전체 클라우드 리소스 접근
3. **URL 검증만으로는 불충분**: IP 스푸핑, 리다이렉션, DNS 리바인딩 고려
4. **화이트리스트 방식이 가장 안전**: 필요한 도메인만 명시적으로 허용
5. **IMDSv2 필수**: AWS 환경에서는 반드시 IMDSv2를 강제
6. **리다이렉션 비활성화**: RestTemplate, WebClient에서 명시적으로 설정
7. **타임아웃 + 포트 제한**: 내부 서비스 연결 최소화

---

## 🤔 생각해볼 문제 (+ 해설)

### Q1. 다음 URL은 왜 위험한가?
```
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity
```
**해설**: Google Cloud의 메타데이터 서비스. GCP 환경에서 SSRF 발생 시 서비스 계정 토큰을 획득할 수 있으며, 이를 이용해 GCS(Cloud Storage), BigQuery, Datastore 등 모든 GCP 리소스에 접근 가능합니다.

### Q2. 화이트리스트 방식의 한계는 무엇인가?
**해설**: 
- **DNS 리바인딩 공격**: 캐싱된 DNS 응답을 활용해, 화이트리스트 검증 후 DNS를 조작하면 다른 IP로 연결될 수 있음
- **해결책**: DNS 응답을 매번 재확인하거나, IP 주소 자체를 화이트리스트에 등록

### Q3. 다음 코드의 문제점은?
```java
URL url = new URL(userInput);
if (!url.getHost().equals("api.example.com")) {
    throw new Exception("Blocked");
}
InetAddress addr = InetAddress.getByName(url.getHost());
```
**해설**: DNS 타임 체크-타임 유스(TOCTOU) 취약점. 검증과 실제 요청 사이에 DNS가 변경될 수 있습니다. 해결책: 검증한 IP 주소를 저장했다가 직접 사용 (호스트명 재조회 금지).

### Q4. 리다이렉션 따라가기가 꼭 필요한가?
**해설**: 요구사항에 따라 다릅니다.
- **필요한 경우**: 서비스 간 리다이렉션이 있는 정상적인 API 사용
- **위험한 경우**: 공격자가 신뢰할 수 있는 도메인 → 내부 IP로의 리다이렉션 체인 구성 가능

**권장**: 기본적으로 비활성화하고, 꼭 필요한 경우만 제한된 수(3회)만 따라가기

<div align="center">

**[홈으로 🏠](../README.md)** | **[다음: 민감 데이터 노출 ➡️](./02-sensitive-data-exposure.md)**

</div>
