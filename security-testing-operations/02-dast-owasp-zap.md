# DAST — OWASP ZAP을 이용한 동적 보안 테스트

---

## 🎯 핵심 질문

- **DAST(Dynamic Application Security Testing)는 SAST와 뭐가 다른가?** SAST는 소스 코드 정적 분석, DAST는 실행 중인 애플리케이션 실제 테스트입니다.
- **OWASP ZAP의 Passive vs Active 스캔은?** Passive는 네트워크 트래픽 분석, Active는 애플리케이션을 직접 공격하여 취약점 확인입니다.
- **ZAP을 CI/CD에 통합하려면?** Docker로 스캔 후 JSON 리포트 생성, 임계값 초과 시 빌드 실패합니다.
- **false positive를 어떻게 관리하는가?** ZAP Alert Filter로 제외 규칙 설정합니다.

---

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

### Adobe Flash 원격 코드 실행 (CVE-2015-3113)
**배경**: SAST만으로는 탐지 불가능한 취약점. Active 공격을 통해서만 발견.

**문제**:
```
1. SAST: Flash 바이너리는 정적 분석 불가능
2. DAST(Active Scan): 
   - ZAP이 Flash 파일 요청 시 특정 페이로드 전송
   - 비정상적인 응답 감지 → 취약점 확인
   - 실제 RCE 테스트로 확인
```

---

## 😱 취약한 코드/설정 (Before — 원리를 모를 때의 구현)

### 취약 1: DAST 테스트 미실시

```yaml
# ❌ 위험: CI/CD에서 보안 테스트 없음
name: Build
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Build
        run: ./gradlew build
      
      # DAST 스캔 완전 생략
      - name: Deploy to Staging
        run: deploy.sh
      
      # 배포 후 보안 테스트도 없음
```

### 취약 2: 취약한 애플리케이션 설정

```java
@Configuration
public class InsecureWebConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf().disable()  // ❌ CSRF 보호 비활성화
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())  // ❌ 인증 필요 없음
            .headers().disable();  // ❌ 보안 헤더 비활성화
        
        return http.build();
    }

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                    .allowedOrigins("*")  // ❌ 모든 도메인 허용
                    .allowedMethods("GET", "POST", "PUT", "DELETE");
            }
        };
    }
}

@RestController
public class InsecureApiController {

    // ❌ 위험: 사용자 입력을 HTML에 그대로 포함 (XSS)
    @GetMapping("/search")
    public String search(@RequestParam String q) {
        return "<h1>Search results for: " + q + "</h1>";
    }

    // ❌ 위험: 파일 경로 조작 (Path Traversal)
    @GetMapping("/download")
    public ResponseEntity<?> download(@RequestParam String file) throws IOException {
        return ResponseEntity.ok(Files.readAllBytes(Paths.get("/uploads/" + file)));
    }

    // ❌ 위험: SQL 인젝션
    @PostMapping("/login")
    public ResponseEntity<?> login(
            @RequestParam String username,
            @RequestParam String password) {
        String sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        return ResponseEntity.ok(sql);
    }
}
```

---

## ✨ 방어 코드/설정 (After — 공격 원리를 알고 설계한 구현)

### 방어 1: 안전한 애플리케이션 구성

```java
@Configuration
@EnableWebSecurity
public class SecureWebConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // ✅ CSRF 보호 활성화
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
            
            // ✅ 명시적 인증
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .requestMatchers("/api/**").authenticated()
                .anyRequest().permitAll())
            
            // ✅ 보안 헤더 추가
            .headers(headers -> headers
                .contentSecurityPolicy("default-src 'self'")
                .and()
                .xssProtection()
                .and()
                .frameOptions().deny())
            
            .formLogin();
        
        return http.build();
    }

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                // ✅ 명시적 도메인만 허용
                registry.addMapping("/api/**")
                    .allowedOrigins("https://trusted-domain.com")
                    .allowedMethods("GET", "POST", "PUT")
                    .allowedHeaders("Content-Type", "Authorization")
                    .maxAge(3600);
            }
        };
    }
}

@RestController
public class SecureApiController {

    @Autowired
    private UserRepository userRepository;

    // ✅ 방어: XSS 방지 (입력 검증 + 출력 인코딩)
    @GetMapping("/search")
    public ResponseEntity<?> search(@RequestParam String q) {
        // 1. 입력 길이 제한
        if (q == null || q.length() > 100) {
            throw new ValidationException("Invalid search query");
        }

        // 2. 데이터 조회 (기본적으로 안전)
        List<Product> results = productRepository.searchByKeyword(q);

        // 3. JSON 응답 (자동 XSS 방지)
        return ResponseEntity.ok(results);
        // HTML이 아니라 JSON으로 응답하므로 XSS 우려 없음
    }

    // ✅ 방어: Path Traversal 방지
    @GetMapping("/download")
    public ResponseEntity<?> download(@RequestParam String filename) throws IOException {
        // 1. 경로 정규화
        Path requestedPath = Paths.get("/uploads/" + filename).normalize();
        Path uploadDir = Paths.get("/uploads").toAbsolutePath();
        
        // 2. 디렉토리 벗어남 방지
        if (!requestedPath.getParent().equals(uploadDir)) {
            throw new SecurityException("Invalid file path");
        }

        // 3. 파일 존재 확인
        if (!Files.exists(requestedPath)) {
            return ResponseEntity.notFound().build();
        }

        // 4. 안전한 파일만 다운로드
        if (!requestedPath.toString().endsWith(".pdf")) {
            throw new SecurityException("Only PDF files allowed");
        }

        return ResponseEntity.ok(Files.readAllBytes(requestedPath));
    }

    // ✅ 방어: SQL 인젝션 방지 (JPA 사용)
    @PostMapping("/login")
    public ResponseEntity<?> login(
            @RequestParam String username,
            @RequestParam String password) {
        
        // 1. 파라미터 검증
        if (username == null || username.length() > 50) {
            throw new ValidationException("Invalid username");
        }

        // 2. JPA Repository 사용 (자동 파라미터화)
        User user = userRepository.findByUsername(username);

        // 3. 비밀번호 검증
        if (user == null || !passwordEncoder.matches(password, user.getPasswordHash())) {
            throw new AuthenticationException("Invalid credentials");
        }

        // 4. 로그인 토큰 생성
        String token = jwtTokenProvider.generateToken(user.getId());
        return ResponseEntity.ok(new LoginResponse(token));
    }
}
```

### 방어 2: OWASP ZAP Docker 스캔

```yaml
# .github/workflows/dast.yml
name: Dynamic Security Test (DAST)

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  dast:
    runs-on: ubuntu-latest
    
    services:
      # ✅ 테스트할 애플리케이션 (스테이징)
      app:
        image: myapp:latest
        ports:
          - 8080:8080
        options: --health-cmd="curl http://localhost:8080/actuator/health" --health-interval=10s

    steps:
      - uses: actions/checkout@v4
      
      # ✅ 애플리케이션 헬스 체크
      - name: Wait for App to be Ready
        run: |
          for i in {1..30}; do
            if curl -f http://localhost:8080/actuator/health; then
              echo "App is ready"
              exit 0
            fi
            echo "Waiting for app... ($i)"
            sleep 2
          done
          exit 1
      
      # ✅ OWASP ZAP Passive 스캔 (안전, 빠름)
      - name: ZAP Passive Scan
        uses: zaproxy/action-full-scan@v0.7.0
        with:
          target: 'http://localhost:8080'
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a'  # 모든 플러그인 활성화
      
      # ✅ ZAP Active 스캔 (공격 시뮬레이션, 느림)
      - name: ZAP Active Scan
        uses: zaproxy/action-baseline@v0.7.0
        with:
          target: 'http://localhost:8080'
          rules_file_name: '.zap/rules.tsv'
      
      # ✅ 리포트 생성
      - name: Upload ZAP Report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: zap-scan-report
          path: report_html.html
      
      # ✅ 취약점 임계값 확인
      - name: Check ZAP Results
        if: always()
        run: |
          # JSON 리포트에서 CRITICAL/HIGH 취약점 수 확인
          CRITICAL=$(jq '.alerts[] | select(.riskcode=="3") | length' report.json)
          HIGH=$(jq '.alerts[] | select(.riskcode=="2") | length' report.json)
          
          if [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 3 ]; then
            echo "❌ Security threshold exceeded"
            echo "CRITICAL: $CRITICAL, HIGH: $HIGH"
            exit 1
          fi
          echo "✅ Security checks passed"
```

### 방어 3: ZAP 규칙 파일 설정

```tsv
# .zap/rules.tsv (false positive 제외)
10002	WARN	# Cookie without Secure Flag
10003	WARN	# Cookie without HttpOnly Flag
10023	INFO	# Information Disclosure - Debug Error Page (개발 환경에서 제외)
20000	WARN	# Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
20001	WARN	# SQL Injection
30001	INFO	# Buffer Overflow
```

### 방어 4: ZAP 명령줄 스캔 (로컬)

```bash
# 1. ZAP Docker 이미지 실행
docker run -t owasp/zap2docker-stable zap-baseline.py \
  -t http://localhost:8080 \
  -r zap-report.html

# 2. Active 스캔 (더 철저함)
docker run -t owasp/zap2docker-stable zap-full-scan.py \
  -t http://localhost:8080 \
  -r zap-report.html \
  -J zap-report.json

# 3. 스캔 결과 JSON 분석
docker run -v $(pwd):/zap/wrk owasp/zap2docker-standard \
  python /zap/wrk/analyze-zap.py zap-report.json
```

**analyze-zap.py** (결과 분석 스크립트):
```python
#!/usr/bin/env python3
import json
import sys

def analyze_zap_report(report_file):
    with open(report_file, 'r') as f:
        data = json.load(f)
    
    alerts = data.get('@alerts', [])
    
    # 심각도별 분류
    critical = [a for a in alerts if a.get('@risk') == 'High']
    high = [a for a in alerts if a.get('@risk') == 'Medium']
    
    print(f"Total Issues: {len(alerts)}")
    print(f"Critical: {len(critical)}")
    print(f"High: {len(high)}")
    
    # Critical 이슈 상세
    for alert in critical:
        print(f"\n❌ {alert['name']}")
        print(f"   URL: {alert['url']}")
        print(f"   Risk: {alert['risk']}")
    
    # 임계값 확인
    if len(critical) > 0 or len(high) > 5:
        print("\n⚠️  Threshold exceeded!")
        sys.exit(1)
    else:
        print("\n✅ Security checks passed")
        sys.exit(0)

if __name__ == '__main__':
    analyze_zap_report(sys.argv[1])
```

### 방어 5: ZAP API를 통한 프로그래매틱 스캔

```python
#!/usr/bin/env python3
# zap-scan.py

import requests
import json
import time
from zapv2 import ZAPv2

class ZapScanner:
    def __init__(self, target_url, zap_url='http://localhost:8080'):
        self.target = target_url
        self.zap = ZAPv2(proxies={'http': zap_url, 'https': zap_url})
    
    def run_scan(self):
        """✅ 전체 보안 스캔 실행"""
        
        # 1. 액세스 트리 빌드 (애플리케이션 매핑)
        print("[*] Building access tree...")
        self.zap.spider.scan(self.target)
        while int(self.zap.spider.status()) < 100:
            print(f"  Spider progress: {self.zap.spider.status()}%")
            time.sleep(2)
        
        # 2. Passive 스캔 (네트워크 트래픽 분석)
        print("[*] Running passive scan...")
        while int(self.zap.pscan.records_to_scan()) > 0:
            print(f"  Passive scan progress: {self.zap.pscan.records_to_scan()} records left")
            time.sleep(1)
        
        # 3. Active 스캔 (공격 시뮬레이션)
        print("[*] Running active scan...")
        scan_id = self.zap.ascan.scan(self.target)
        while int(self.zap.ascan.status(scan_id)) < 100:
            print(f"  Active scan progress: {self.zap.ascan.status(scan_id)}%")
            time.sleep(5)
        
        # 4. 결과 수집
        alerts = self.zap.alert.alerts(baseurl=self.target)
        return self.analyze_alerts(alerts)
    
    def analyze_alerts(self, alerts):
        """✅ 취약점 분석 및 분류"""
        
        results = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        
        for alert in alerts:
            risk = alert.get('risk', 'Unknown').lower()
            results[risk].append({
                'name': alert['alert'],
                'url': alert['url'],
                'description': alert['description'],
                'solution': alert.get('solution', 'N/A')
            })
        
        # 리포트 출력
        print("\n=== Scan Results ===")
        print(f"Critical: {len(results['critical'])}")
        print(f"High: {len(results['high'])}")
        print(f"Medium: {len(results['medium'])}")
        print(f"Low: {len(results['low'])}")
        
        # JSON 저장
        with open('zap-results.json', 'w') as f:
            json.dump(results, f, indent=2)
        
        # 실패 판단
        if len(results['critical']) > 0 or len(results['high']) > 5:
            print("\n❌ Security threshold exceeded!")
            return False
        
        print("\n✅ Security checks passed!")
        return True

if __name__ == '__main__':
    scanner = ZapScanner('http://localhost:8080')
    success = scanner.run_scan()
    exit(0 if success else 1)
```

---

## 🔬 공격 원리 분석 (DAST 탐지 메커니즘)

### ZAP Active 스캔 공격 페이로드 예시

```
1. XSS 탐지:
   - 정상 요청: GET /search?q=apple
   - ZAP 공격: GET /search?q=<img src=x onerror="alert('xss')">
   - 응답이 페이로드를 그대로 포함 → XSS 취약점 확인

2. SQL 인젝션 탐지:
   - 정상 요청: GET /users?id=1
   - ZAP 공격 #1: GET /users?id=1' OR '1'='1
   - ZAP 공격 #2: GET /users?id=1 UNION SELECT NULL, NULL--
   - 응답 시간, 에러 메시지, 데이터 변화 → SQL 인젝션 확인

3. Path Traversal 탐지:
   - 정상 요청: GET /download?file=report.pdf
   - ZAP 공격: GET /download?file=../../../../etc/passwd
   - 정상과 다른 콘텐츠 반환 → 취약점 확인
```

---

## 💻 실전 실험 (취약점 재현 → 공격 → 방어 검증)

### 실험 1: ZAP로 취약한 애플리케이션 스캔

```bash
# 1. 취약한 애플리케이션 시작
docker run -p 8080:8080 vulnerable-app:latest

# 2. ZAP 스캔 실행
docker run -t owasp/zap2docker-baseline:latest \
  zap-baseline.py -t http://host.docker.internal:8080 \
  -r /zap/wrk/report.html

# 3. 결과 확인
open report.html

# 발견된 취약점:
# ❌ Cross-site Scripting (XSS) - /search endpoint
# ❌ SQL Injection - /login endpoint  
# ❌ Missing Security Headers - all pages
# ❌ Path Traversal - /download endpoint
```

### 실험 2: 방어 후 재스캔

```bash
# 1. 안전한 버전으로 업데이트
docker run -p 8080:8080 secure-app:latest

# 2. 동일한 ZAP 스캔
docker run -t owasp/zap2docker-baseline:latest \
  zap-baseline.py -t http://host.docker.internal:8080 \
  -r /zap/wrk/report-secure.html

# 3. 결과 비교
# 이전: 8개 취약점 발견
# 현재: 0개 취약점 발견
```

---

## 📌 핵심 정리

1. **DAST는 필수**: SAST는 정적 분석, DAST는 실제 실행 환경 테스트
2. **OWASP ZAP**: 무료, 오픈소스, 자동 스캔 가능
3. **Passive vs Active**: Passive는 안전하고 빠름, Active는 공격 시뮬레이션
4. **CI/CD 통합**: 배포 전 자동 스캔으로 취약점 조기 발견
5. **False Positive 관리**: 규칙 파일로 제외 설정
6. **임계값 설정**: Critical=0, High≤3 기준으로 빌드 실패 판단

<div align="center">

**[⬅️ 이전: SAST 자동화](./01-sast-pipeline.md)** | **[홈으로 🏠](../README.md)** | **[다음: 침투 테스트 방법론 ➡️](./03-penetration-testing.md)**

</div>
