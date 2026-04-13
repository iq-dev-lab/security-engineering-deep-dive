# CSRF 공격 (Cross-Site Request Forgery)
---

## 🎯 핵심 질문
Same-Origin Policy가 있는데 왜 CSRF 공격이 가능한가? 브라우저가 다른 도메인의 요청을 차단하는데, 어떻게 공격자가 피해자 계정으로 요청을 보낼 수 있는가?

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

### Netflix CSRF 사건 (2008)
공격자가 다음과 같은 악의적 웹사이트를 만들었다:
```html
<img src="https://www.netflix.com/api/rentals?movie_id=12345&action=rent">
```
- 사용자가 공격자 사이트 방문
- 자동으로 Netflix에 요청이 전송 (쿠키 자동 포함)
- 사용자 몰래 영화 렌탈됨
- 신용카드에 청구

### Facebook CSRF 벌크 친구 추가 (2009)
공격자가 다음을 포함한 페이지를 만들었다:
```html
<form method="POST" action="https://www.facebook.com/friends/add">
  <input name="friend_id" value="attacker_id">
  <script>document.forms[0].submit();</script>
</form>
```
- 사용자가 링크 클릭
- 모두가 자동으로 공격자를 친구 추가
- 공격자 계정으로 스팸/정보 수집

### 은행 송금 CSRF
공격자가 다음을 사용했다:
```html
<iframe style="display:none" src="https://bank.com/transfer?amount=10000&to=attacker_account"></iframe>
```
- 사용자가 은행 사이트에 로그인한 상태
- 공격자 사이트 방문
- 자동으로 은행에서 송금

### 인증 도메인 변경 CSRF
공격자가 다음을 사용했다:
```html
<img src="https://router.local/admin/change_password?password=hacker123">
```
- 사용자 라우터의 기본 비밀번호로 접속
- 공격자가 비밀번호 변경
- 사용자는 자신의 Wi-Fi에 접속 불가

## 😱 취약한 코드 (Before — 원리를 모를 때의 구현)

### 1. CSRF 토큰이 없는 경우

```java
// ❌ 취약한 코드: CSRF 방어 없음
@RestController
public class VulnerableTransferController {
    
    @PostMapping("/api/transfer")
    public ResponseEntity<String> transfer(
            @RequestParam long amount,
            @RequestParam String toAccount) {
        
        // ❌ 문제: CSRF 토큰 검증 없음
        // SOP는 JavaScript에서만 적용되고, HTML form은 예외
        
        User currentUser = getCurrentUser();
        Account account = accountService.getAccount(currentUser.getId());
        
        // 즉시 송금 처리
        account.transferTo(toAccount, amount);
        
        return ResponseEntity.ok("송금 완료: " + toAccount + ", 금액: " + amount);
    }
}

// 공격 시나리오
// 1. 사용자가 은행 사이트에 로그인한 상태
//    쿠키: JSESSIONID=user_session_123
//
// 2. 사용자가 공격자 사이트 방문
//    attacker.com이 다음 HTML을 제공:
//
// <form method="POST" action="https://bank.com/api/transfer" style="display:none">
//   <input name="amount" value="100000">
//   <input name="toAccount" value="attacker_account">
//   <script>
//     document.forms[0].submit();
//   </script>
// </form>
//
// 3. 브라우저가 자동으로 폼 제출
//    POST /api/transfer HTTP/1.1
//    Host: bank.com
//    Cookie: JSESSIONID=user_session_123
//    
//    amount=100000&toAccount=attacker_account
//
// 4. 서버가 처리
//    - JSESSIONID 유효함 (같은 브라우저, 같은 사용자)
//    - CSRF 토큰 검증 안함 (CSRF 토큰이 없음)
//    - 송금 완료
//
// 5. 사용자 계정에서 100,000원 감소
//    공격자 계정에 100,000원 증가
```

### 2. CSRF 토큰이 있지만 검증이 약한 경우

```java
// ❌ 취약한 코드: CSRF 토큰 검증이 불완전
@RestController
public class WeakCsrfProtectionController {
    
    @PostMapping("/api/transfer")
    public ResponseEntity<String> transfer(
            @RequestParam long amount,
            @RequestParam String toAccount,
            @RequestParam String csrfToken) {  // ← 파라미터로 받음
        
        HttpSession session = request.getSession();
        String sessionToken = (String) session.getAttribute("csrf_token");
        
        // ❌ 문제 1: CSRF 토큰이 파라미터/쿼리스트링으로 전달
        // GET 요청으로도 접근 가능, 리퍼러 로그에 남음, URL에 노출됨
        
        if (csrfToken.equals(sessionToken)) {
            // ❌ 문제 2: 단순 문자열 비교만 수행
            // 공격자가 토큰 형식을 알면, 토큰 생성기의 약점 이용 가능
            
            User currentUser = getCurrentUser();
            Account account = accountService.getAccount(currentUser.getId());
            account.transferTo(toAccount, amount);
            
            return ResponseEntity.ok("송금 완료");
        } else {
            return ResponseEntity.status(403).body("CSRF 검증 실패");
        }
    }
}

// 공격 시나리오
// 1. 공격자가 유효한 CSRF 토큰 형식을 추측
//    예: 예측 가능한 패턴이면 토큰 조작 가능
//
// 2. 또는 리퍼러 헤더를 통해 토큰 획득
//    https://attacker.com/?csrf_token=abc123
//    → 로그에 전체 URL 기록됨
//
// 3. 공격자가 GET 요청으로 변조
//    https://bank.com/api/transfer?amount=100000&toAccount=attacker&csrfToken=abc123
```

### 3. SameSite 쿠키 속성이 없는 경우

```java
// ❌ 취약한 코드: SameSite 속성 미설정
@Configuration
public class VulnerableCookieConfig {
    
    @Bean
    public ServletContextInitializer servletContextInitializer() {
        return servletContext -> {
            SessionCookieConfig sessionCookieConfig = 
                servletContext.getSessionCookieConfig();
            
            // ❌ SameSite 속성 설정 안함
            sessionCookieConfig.setHttpOnly(true);
            sessionCookieConfig.setSecure(true);
            // setAttribute("SameSite", "Strict");  // ← 없음!
        };
    }
}

// 공격 시나리오
// SameSite=None인 경우, 다른 도메인 요청에도 쿠키 전송됨
// SameSite=Lax: 최상위 이동(링크 클릭)에서는 쿠키 전송
// SameSite=Strict: 같은 사이트 요청에서만 쿠키 전송
//
// 공격자가 다음을 사용하면:
// <form method="POST" action="https://bank.com/api/transfer">
//   ...
// </form>
//
// SameSite 미설정 또는 Lax인 경우: 쿠키 포함되어 공격 성공
// SameSite=Strict인 경우: 쿠키 미포함, 인증 실패 → 공격 실패
```

### 4. REST API에서 CSRF 보호를 완전히 무시하는 경우

```java
// ❌ 취약한 코드: REST API의 CSRF 비활성화
@Configuration
public class WeakApiSecurityConfig {
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf()
                .disable()  // ❌ CSRF 보호 완전 비활성화
                .and()
            .build();
        
        return http.build();
    }
}

// 공격 시나리오
// REST API이므로 CSRF가 필요 없다고 생각할 수 있지만:
//
// 1. 공격자가 JavaScript로 클로스 요청을 보냄 (fetch API)
// 2. 문제: CORS 정책이 없으면 Cross-Origin 요청 차단
// 3. 하지만 Simple Request는 CORS 사전 확인 없음:
//    - GET, HEAD, POST (Content-Type: application/x-www-form-urlencoded)
//
// 4. 공격자가 form으로 POST 요청:
// <form method="POST" action="https://api.bank.com/transfer" enctype="application/x-www-form-urlencoded">
//   <input name="amount" value="100000">
//   <script>document.forms[0].submit();</script>
// </form>
//
// 5. 결과: CSRF 공격 성공 (CSRF 토큰 없으므로)
```

## ✨ 방어 코드 (After — 공격 원리를 알고 설계한 구현)

### 1. CSRF 토큰 기반 방어 (Spring Security)

```java
// ✅ 안전한 코드: Spring Security CSRF 보호
@Configuration
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // ✅ CSRF 보호 활성화 (기본값)
            .csrf(csrf -> csrf
                // ✅ CSRF 토큰을 HTTP 헤더 또는 폼 파라미터에서 읽기
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                // ✅ 토큰을 쿠키에 저장 (HttpOnly=false: JavaScript에서 접근 가능)
                // ✅ 하지만 쿠키 자체는 SameSite=Strict로 보호
                
                // ✅ GET, DELETE 등 안전한 HTTP 메서드 제외
                // POST, PUT, DELETE 등 상태 변경 메서드에만 적용
                .ignoringRequestMatchers("/api/public/**")
            )
            .sessionManagement()
                .sessionFixation().migrateSession()
                .and()
            .authorizeRequests()
                .antMatchers("/", "/login", "/register").permitAll()
                .anyRequest().authenticated()
                .and()
            .formLogin()
                .and()
            .build();
        
        return http.build();
    }
}

// CSRF 토큰 엔드포인트
@RestController
public class CsrfTokenController {
    
    @GetMapping("/api/csrf-token")
    public ResponseEntity<CsrfTokenResponse> getCsrfToken(
            CsrfToken csrfToken) {
        
        // ✅ Spring Security가 자동으로 토큰 생성
        return ResponseEntity.ok(new CsrfTokenResponse(
            csrfToken.getHeaderName(),  // "X-CSRF-TOKEN"
            csrfToken.getToken()
        ));
    }
}

class CsrfTokenResponse {
    public String headerName;
    public String token;
    
    public CsrfTokenResponse(String headerName, String token) {
        this.headerName = headerName;
        this.token = token;
    }
}

// 클라이언트 코드 (JavaScript)
async function getTransferForm() {
    // ✅ 1. CSRF 토큰 획득
    const csrfResponse = await fetch('/api/csrf-token');
    const { headerName, token } = await csrfResponse.json();
    
    // ✅ 2. 폼 생성 및 토큰 삽입
    return {
        csrfToken: token,
        csrfHeaderName: headerName
    };
}

async function transfer(amount, toAccount) {
    const { csrfToken, csrfHeaderName } = await getTransferForm();
    
    // ✅ 3. CSRF 토큰을 HTTP 헤더에 포함하여 요청
    const response = await fetch('/api/transfer', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            [csrfHeaderName]: csrfToken  // ← CSRF 토큰 포함
        },
        body: JSON.stringify({
            amount: amount,
            toAccount: toAccount
        })
    });
    
    return await response.json();
}
```

### 2. SameSite 쿠키 속성 설정

```java
// ✅ 안전한 코드: SameSite 쿠키 속성
@Configuration
public class SecureCookieConfig {
    
    @Bean
    public ServletContextInitializer servletContextInitializer() {
        return servletContext -> {
            SessionCookieConfig sessionCookieConfig = 
                servletContext.getSessionCookieConfig();
            
            // ✅ 1. HttpOnly: JavaScript에서 접근 차단 (XSS 방지)
            sessionCookieConfig.setHttpOnly(true);
            
            // ✅ 2. Secure: HTTPS에서만 전송 (중간자 공격 방지)
            sessionCookieConfig.setSecure(true);
            
            // ✅ 3. SameSite: 크로스 사이트 요청에서 쿠키 전송 차단 (CSRF 방지)
            // Strict: 가장 강함 (크로스 사이트 요청에서 쿠키 미전송)
            // Lax: 중간 강도 (최상위 이동에서만 쿠키 전송)
            // None: 모든 크로스 사이트 요청에서 쿠키 전송 (Secure 필수)
            sessionCookieConfig.setAttribute("SameSite", "Strict");
            
            // ✅ 4. Path: 특정 경로에서만 쿠키 사용
            sessionCookieConfig.setPath("/");
        };
    }
}

// Spring Boot 설정 파일
// application.properties
// server.servlet.session.cookie.http-only=true
// server.servlet.session.cookie.secure=true
// server.servlet.session.cookie.same-site=strict
// server.servlet.session.cookie.path=/

// ❌ 주의: Lax 설정의 위험성
// SameSite=Lax인 경우, 최상위 이동(링크 클릭)에서는 쿠키 전송됨
// <a href="https://bank.com/api/transfer?amount=100000">좋은 소식</a>
// 사용자가 링크 클릭 시, 쿠키 포함되어 요청됨
// 따라서 Lax는 안전하지 않을 수 있음 → Strict 권장

// ✅ SameSite 시대의 CSRF 공격 시뮬레이션
// 1. 사용자가 bank.com에 로그인
//    쿠키: JSESSIONID=user123; SameSite=Strict
//
// 2. 공격자 사이트(attacker.com) 방문
//
// 3. 공격자가 다음 폼 제출 시도
//    <form method="POST" action="https://bank.com/api/transfer">
//      <input name="amount" value="100000">
//    </form>
//
// 4. 브라우저 동작
//    - Origin: attacker.com
//    - Target: bank.com
//    - SameSite=Strict이므로 쿠키 미전송
//
// 5. 서버 처리
//    - 쿠키 없음 → 인증되지 않음 → 401 Unauthorized
//    - 공격 실패!
```

### 3. 커스텀 CSRF 토큰 관리

```java
// ✅ 안전한 코드: 커스텀 CSRF 토큰 관리
@Component
public class CustomCsrfTokenManager {
    
    @Autowired
    private RedisTemplate<String, String> redisTemplate;
    
    private static final String CSRF_TOKEN_PREFIX = "csrf_token:";
    private static final long CSRF_TOKEN_EXPIRY_SECONDS = 3600;  // 1시간
    
    // CSRF 토큰 생성
    public String generateToken(String sessionId) {
        // ✅ 1. 강력한 랜덤 토큰 생성 (256비트)
        String token = UUID.randomUUID().toString() + 
                       UUID.randomUUID().toString();
        
        // ✅ 2. Redis에 저장 (sessionId 키로)
        String key = CSRF_TOKEN_PREFIX + sessionId;
        redisTemplate.opsForValue().set(
            key,
            token,
            CSRF_TOKEN_EXPIRY_SECONDS,
            TimeUnit.SECONDS
        );
        
        return token;
    }
    
    // CSRF 토큰 검증
    public boolean validateToken(String sessionId, String token) {
        String key = CSRF_TOKEN_PREFIX + sessionId;
        String storedToken = redisTemplate.opsForValue().get(key);
        
        // ✅ 토큰이 일치하고, Redis에서 조회되면 유효
        if (storedToken != null && storedToken.equals(token)) {
            // ✅ 일회용 토큰: 사용 후 삭제
            redisTemplate.delete(key);
            return true;
        }
        
        return false;
    }
    
    // CSRF 토큰 갱신 (매 페이지 로드 시)
    public String refreshToken(String sessionId) {
        // 기존 토큰 삭제
        String key = CSRF_TOKEN_PREFIX + sessionId;
        redisTemplate.delete(key);
        
        // 새 토큰 생성
        return generateToken(sessionId);
    }
}

// 필터에서 CSRF 토큰 검증
@Component
public class CustomCsrfFilter extends OncePerRequestFilter {
    
    @Autowired
    private CustomCsrfTokenManager csrfTokenManager;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        
        // ✅ POST, PUT, DELETE 등 상태 변경 요청에만 검증
        if (isStateMutatingRequest(request)) {
            HttpSession session = request.getSession(false);
            if (session != null) {
                // ✅ 토큰을 헤더 또는 파라미터에서 읽기
                String csrfToken = request.getHeader("X-CSRF-TOKEN");
                if (csrfToken == null) {
                    csrfToken = request.getParameter("_csrf");
                }
                
                // ✅ 토큰 검증
                if (!csrfTokenManager.validateToken(session.getId(), csrfToken)) {
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    response.getWriter().write("CSRF 토큰 검증 실패");
                    return;
                }
            }
        }
        
        filterChain.doFilter(request, response);
    }
    
    private boolean isStateMutatingRequest(HttpServletRequest request) {
        String method = request.getMethod();
        return !method.equals("GET") && !method.equals("HEAD") && 
               !method.equals("OPTIONS") && !method.equals("TRACE");
    }
}
```

### 4. CORS와 CSRF의 관계 이해

```java
// ✅ 안전한 코드: CORS + CSRF 통합 보호
@Configuration
public class CorsAndCsrfConfig {
    
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry
                    // ✅ 특정 도메인만 허용 (와일드카드 * 금지)
                    .addMapping("/api/**")
                    .allowedOrigins("https://trusted-client.com")
                    // ✅ 신뢰할 수 있는 HTTP 메서드만 허용
                    .allowedMethods("GET", "POST", "PUT", "DELETE")
                    // ✅ 신뢰할 수 있는 헤더만 허용
                    .allowedHeaders("Content-Type", "X-CSRF-TOKEN")
                    // ✅ 자격증명(쿠키) 포함
                    .allowCredentials(true)
                    // ✅ CORS 사전 검사 캐시 시간
                    .maxAge(3600);
            }
        };
    }
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // ✅ CSRF 보호 활성화
            .csrf(csrf -> csrf
                .csrfTokenRepository(
                    CookieCsrfTokenRepository.withHttpOnlyFalse()
                )
            )
            // ✅ CORS 설정 적용
            .cors(cors -> cors.configurationSource(request -> {
                CorsConfiguration config = new CorsConfiguration();
                config.setAllowedOrigins(List.of("https://trusted-client.com"));
                config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
                config.setAllowedHeaders(List.of("*"));
                config.setAllowCredentials(true);
                return config;
            }))
            .build();
        
        return http.build();
    }
}

// ✅ CORS + CSRF 흐름
// 1. 클라이언트가 다른 도메인의 API 호출 시도
//    Origin: https://trusted-client.com
//    Target: https://api.bank.com/transfer
//
// 2. 브라우저가 CORS 사전 검사 (Preflight) 요청
//    OPTIONS /transfer
//    Access-Control-Request-Method: POST
//
// 3. 서버가 CORS 허용 여부 확인
//    ✅ trusted-client.com이 화이트리스트에 있음 → 허용
//    Access-Control-Allow-Origin: https://trusted-client.com
//
// 4. 실제 POST 요청 전송
//    POST /transfer
//    X-CSRF-TOKEN: abc123def456...
//
// 5. 서버가 CSRF 토큰 검증
//    ✅ 토큰 유효 → 송금 처리
```

## 🔬 공격 원리 분석 (공격자 관점의 내부 동작)

### Same-Origin Policy의 한계

```
┌─────────────────────────────────────────────────────┐
│ SOP (Same-Origin Policy)가 차단하는 것              │
├─────────────────────────────────────────────────────┤
│ 1. JavaScript의 XMLHttpRequest/fetch                │
│    Origin: attacker.com                             │
│    Target: bank.com                                 │
│    → ❌ 차단됨                                       │
│                                                      │
│ 2. JavaScript에서 응답 읽기                         │
│    CORS 헤더 없으면 응답 body 접근 불가             │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│ SOP가 허용하는 것 (CSRF 공격 가능)                  │
├─────────────────────────────────────────────────────┤
│ 1. HTML 폼 제출                                     │
│    <form method="POST" action="https://bank.com">   │
│    → ✅ 허용됨 (쿠키 자동 포함)                     │
│                                                      │
│ 2. 링크(<a>)                                        │
│    <a href="https://bank.com/api/transfer">         │
│    → ✅ 허용됨                                      │
│                                                      │
│ 3. 이미지(<img>)                                    │
│    <img src="https://bank.com/api/transfer">        │
│    → ✅ 허용됨 (GET 요청)                          │
│                                                      │
│ 4. 스크립트(<script>)                               │
│    <script src="https://bank.com/api/transfer">     │
│    → ✅ 허용됨                                      │
└─────────────────────────────────────────────────────┘
```

### CSRF 공격의 단계별 진행

```
Step 1: 사용자 로그인
├─ 사용자가 bank.com에 로그인
├─ 브라우저에 쿠키 저장: JSESSIONID=user_session_123
└─ 쿠키 속성: HttpOnly, Secure, SameSite=None (취약한 경우)

Step 2: 공격 페이지 구성
├─ 공격자가 attacker.com 운영
├─ 다음 코드를 포함한 페이지 준비:
├─ <form method="POST" action="https://bank.com/transfer">
├─   <input name="amount" value="100000">
├─   <input name="toAccount" value="attacker_account">
├─   <script>document.forms[0].submit();</script>
├─ </form>
└─ (또는 <img src="..."> 태그로 자동 요청)

Step 3: 사용자 유도
├─ 공격자가 사용자를 attacker.com으로 유도
├─ 방법 1: 이메일 링크
├─ 방법 2: 소셜 미디어 링크
├─ 방법 3: 광고 클릭
└─ 방법 4: 검색 결과

Step 4: 자동 요청 전송
├─ 사용자가 attacker.com 방문
├─ JavaScript가 실행되어 폼 자동 제출
├─ POST /transfer HTTP/1.1
├─ Host: bank.com
├─ Cookie: JSESSIONID=user_session_123
├─ (CSRF 토큰 없음)
└─ amount=100000&toAccount=attacker_account

Step 5: 서버 처리
├─ JSESSIONID 쿠키로 사용자 인증 확인
├─ ❌ CSRF 토큰 검증 없음 (또는 약한 검증)
├─ 송금 처리 → 공격 성공
└─ 사용자는 몰래 송금된 사실을 나중에 발견

Step 6: 피해
├─ 계좌에서 100,000원 감소
├─ 공격자 계좌에 100,000원 증가
└─ 사용자가 기록된 모든 거래를 추적해야 함
```

## 💻 실전 실험 (취약점 재현 → 공격 → 방어 검증)

### 실험 1: CSRF 토큰 없이 공격

```html
<!-- attacker.html -->
<html>
<head>
    <title>멋진 뉴스</title>
</head>
<body>
    <h1>오늘의 뉴스</h1>
    <p>클릭해서 계속 읽기:</p>
    
    <!-- ❌ 취약한 서버: CSRF 토큰 검증 없음 -->
    <form method="POST" action="https://bank.com/api/transfer" style="display:none">
        <input name="amount" value="100000">
        <input name="toAccount" value="attacker_account">
        <script>
            document.forms[0].submit();
        </script>
    </form>
    
    <p>뉴스 내용...</p>
</body>
</html>

<!-- 또는 이미지로 자동 요청 (GET만 가능) -->
<img src="https://bank.com/api/transfer?amount=100000&toAccount=attacker" style="display:none">
```

### 실험 2: CSRF 토큰으로 방어

```java
// 테스트 코드
@SpringBootTest
public class CsrfProtectionTest {
    
    @Autowired
    private MockMvc mockMvc;
    
    @Autowired
    private CsrfTokenRepository csrfTokenRepository;
    
    @Test
    public void testCsrfWithoutToken() throws Exception {
        // ❌ CSRF 토큰 없이 POST 요청
        MvcResult result = mockMvc.perform(
            post("/api/transfer")
                .param("amount", "100000")
                .param("toAccount", "attacker")
        )
            .andExpect(status().isForbidden())  // ✅ 거절됨
            .andReturn();
        
        assertEquals("CSRF 토큰 검증 실패", 
            result.getResponse().getContentAsString());
    }
    
    @Test
    public void testCsrfWithValidToken() throws Exception {
        // ✅ 1. CSRF 토큰 획득
        MvcResult tokenResponse = mockMvc.perform(get("/api/csrf-token"))
            .andExpect(status().isOk())
            .andReturn();
        
        String response = tokenResponse.getResponse().getContentAsString();
        JsonObject json = JsonParser.parseString(response).getAsJsonObject();
        String token = json.get("token").getAsString();
        String headerName = json.get("headerName").getAsString();
        
        // ✅ 2. CSRF 토큰과 함께 POST 요청
        MvcResult result = mockMvc.perform(
            post("/api/transfer")
                .param("amount", "100000")
                .param("toAccount", "attacker")
                .header(headerName, token)
        )
            .andExpect(status().isOk())  // ✅ 성공
            .andReturn();
        
        assertEquals("송금 완료", result.getResponse().getContentAsString());
    }
    
    @Test
    public void testCsrfWithInvalidToken() throws Exception {
        // ❌ 잘못된 CSRF 토큰
        MvcResult result = mockMvc.perform(
            post("/api/transfer")
                .param("amount", "100000")
                .param("toAccount", "attacker")
                .header("X-CSRF-TOKEN", "invalid_token")
        )
            .andExpect(status().isForbidden())  // ✅ 거절됨
            .andReturn();
    }
}
```

### 실험 3: SameSite 쿠키 검증

```bash
# curl로 크로스 사이트 요청 시뮬레이션
# 1. SameSite=Strict인 경우
curl -b "JSESSIONID=user123; SameSite=Strict" \
     -X POST \
     -H "Origin: attacker.com" \
     https://bank.com/api/transfer \
     -d "amount=100000&toAccount=attacker"

# 결과: 쿠키가 전송되지 않음 → 401 Unauthorized

# 2. SameSite=None (또는 미설정)인 경우
curl -b "JSESSIONID=user123" \
     -X POST \
     -H "Origin: attacker.com" \
     https://bank.com/api/transfer \
     -d "amount=100000&toAccount=attacker"

# 결과: 쿠키 전송됨 → 200 OK (CSRF 토큰 없으면 공격 성공!)
```

## 📊 공격 성공 조건 vs 방어 성공 조건 비교

| 항목 | 공격 성공 조건 | 방어 성공 조건 |
|------|--------------|--------------|
| **CSRF 토큰** | 없음 또는 약함 | 강력한 토큰 + 검증 |
| **토큰 위치** | 쿼리 파라미터 (노출) | HTTP 헤더 또는 숨겨진 폼 필드 |
| **SameSite** | 미설정 또는 None | Strict (또는 Lax) |
| **쿠키 속성** | HttpOnly 없음 | HttpOnly + Secure + SameSite |
| **요청 검증** | Origin/Referer 확인 없음 | Origin/Referer 검증 |
| **API 설계** | GET/POST로 상태 변경 | POST/PUT/DELETE로 상태 변경 |

## ⚖️ 트레이드오프 (보안 강화 vs 사용성/성능)

### 1. SameSite=Strict vs 사용성
- **보안**: 크로스 사이트에서 쿠키 미전송 (최강 보안)
- **사용성**: 외부 사이트의 링크 → bank.com 클릭 시 로그아웃 상태
- **트레이드오프**: 
  - SameSite=Lax로 완화 (링크 클릭에서는 쿠키 전송)
  - 또는 SameSite=Strict로 최강 보안 유지

### 2. CSRF 토큰 일회용 vs 사용자 경험
- **보안**: 토큰 사용 후 삭제 (재사용 방지)
- **사용성**: 폼 제출 후 뒤로가기 → 토큰 만료
- **트레이드오프**:
  - 토큰 유효 시간 연장 (1시간)
  - 또는 일회용 토큰 유지 + 사용자 교육

### 3. CORS 화이트리스트 vs 유연성
- **보안**: 신뢰할 수 있는 도메인만 명시 (와일드카드 * 금지)
- **사용성**: 새로운 클라이언트 추가 시 설정 변경 필요
- **트레이드오프**:
  - 동적 CORS 설정 (데이터베이스에서 로드)
  - 또는 정적 화이트리스트 유지

### 4. 상태 변경 메서드 사용 vs REST 관례
- **보안**: POST/PUT/DELETE만 상태 변경 (GET은 조회만)
- **사용성**: REST 관례를 따르는 것이 단순
- **트레이드오프**: REST API 설계 시 항상 GET은 멱등성 유지

## 📌 핵심 정리

1. **CSRF 토큰 검증**
   ```java
   .csrf(csrf -> csrf
       .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
   )
   ```

2. **SameSite 쿠키 속성**
   ```java
   sessionCookieConfig.setAttribute("SameSite", "Strict");
   ```

3. **CSRF 토큰을 HTTP 헤더에 포함**
   ```javascript
   headers: {
       'X-CSRF-TOKEN': csrfToken
   }
   ```

4. **CORS 화이트리스트**
   ```java
   .allowedOrigins("https://trusted-domain.com")  // * 금지
   ```

5. **상태 변경 메서드 사용**
   ```java
   GET: 조회만
   POST/PUT/DELETE: 상태 변경 (CSRF 토큰 필수)
   ```

## 🤔 생각해볼 문제 (+ 해설)

### 문제 1: CSRF 토큰을 쿼리 파라미터에 포함하면 왜 위험한가?
**해설:**
- URL이 로그에 기록됨 → 관리자/IT팀이 볼 수 있음
- 브라우저 히스토리에 남음
- Referer 헤더로 다른 사이트에 전송될 수 있음
- 따라서 토큰은 HTTP 헤더 또는 POST 바디에 포함해야 함

### 문제 2: SameSite=Lax이면 CSRF 공격이 완전히 막히는가?
**해설:**
- 아니다. Lax는 최상위 이동(링크 클릭, 폼 제출)에서 쿠키 전송
- 공격자가 다음을 사용하면 공격 가능:
  ```html
  <a href="https://bank.com/api/transfer?amount=100000">Good news</a>
  ```
- 사용자가 링크 클릭 → GET 요청 → Lax이므로 쿠키 포함
- API가 GET을 지원하면 공격 성공
- 따라서:
  1. GET은 조회만 (상태 변경 X)
  2. 상태 변경은 POST/PUT/DELETE만 (GET 불가)

### 문제 3: REST API에서 CSRF가 불필요한가?
**해설:**
- 아니다! 많은 개발자가 실수함
- REST API도 CSRF 공격에 취약할 수 있음:
  ```html
  <form method="POST" action="https://api.bank.com/transfer">
    <input name="amount" value="100000">
    <script>document.forms[0].submit();</script>
  </form>
  ```
- Content-Type: application/x-www-form-urlencoded는 CORS 사전 검사 생략
- 따라서 REST API도 CSRF 토큰이 필요
- 단, JSON 요청은 기본적으로 CORS 사전 검사를 거치므로 JavaScript에서는 보호됨
- 하지만 HTML 폼이나 이미지 등으로는 여전히 공격 가능

---

<div align="center">

**[⬅️ 이전: 세션 고정 공격](./03-session-fixation.md)** | **[홈으로 🏠](../README.md)** | **[다음: OAuth2 취약점 ➡️](./05-oauth2-vulnerabilities.md)**

</div>
