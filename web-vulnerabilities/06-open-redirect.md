# Open Redirect 공격과 화이트리스트 기반 방어

---

## 🎯 핵심 질문

- `redirect_uri` 파라미터를 조작해서 피싱 사이트로 유도하는 원리는?
- 도메인 검증을 우회하는 기법들: `//`, `\`, `%00` 등
- OAuth 2.0에서 Open Redirect 취약점이 특히 위험한 이유는?
- 화이트리스트 기반 방어를 완벽하게 구현하는 방법은?

---

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

### Facebook의 Open Redirect (2010)
Facebook의 리다이렉트 기능에서 `redirect_uri` 파라미터를 검증하지 않아 공격자가 자신의 피싱 사이트로 사용자를 유도할 수 있었습니다. Facebook 인증을 거친 것처럼 보이는 피싱 페이지로 이동되어 사용자들이 계정 정보를 입력했습니다.

### Google OAuth 2.0 Open Redirect (2014)
Google의 OAuth 2.0 리다이렉트 엔드포인트에서 와일드카드 도메인 검증으로 인해 `attacker.com.google.com` 같은 서브도메인 등록만으로 공격이 가능했습니다.

### Twitter의 도메인 검증 우회 (2015)
Twitter의 로그인 리다이렉트 기능에서 `//` 프로토콜 상대 경로를 지원하면서 `//evil.com`으로 우회가 가능했습니다. `//`은 프로토콜을 현재 프로토콜로 유지하면서 도메인만 변경합니다.

---

## 😱 취약한 코드 (Before — 원리를 모를 때의 구현)

### 1. 리다이렉트 URL 검증 없음

**취약한 Spring Controller**
```java
@Controller
@RequestMapping("/auth")
public class AuthController {
    
    @GetMapping("/callback")
    public String callback(@RequestParam String redirectUrl) {
        // ❌ 문제: redirectUrl을 그대로 리다이렉트
        // 검증 없음!
        return "redirect:" + redirectUrl;
    }
    
    @PostMapping("/login")
    public String login(@RequestParam String username,
                        @RequestParam String password,
                        @RequestParam(required = false) String next) {
        // 로그인 처리...
        if (authenticate(username, password)) {
            // ❌ 문제: next 파라미터를 검증 없이 사용
            return "redirect:" + (next != null ? next : "/dashboard");
        }
        return "redirect:/login?error";
    }
    
    @GetMapping("/logout")
    public String logout(@RequestParam(name = "return_to", required = false) String returnUrl) {
        // 로그아웃 처리...
        
        // ❌ 문제: return_to를 검증 없이 사용
        // http://evil.com, //evil.com, javascript:alert('xss') 등 모두 가능
        if (returnUrl != null && !returnUrl.isEmpty()) {
            return "redirect:" + returnUrl;
        }
        return "redirect:/";
    }
}
```

**공격 시나리오**
```
1단계: 공격자가 피싱 페이지 준비
┌─────────────────────────────────────┐
│ attacker.com/phishing
│
│ "Facebook 로그인이 만료되었습니다"
│ "여기를 클릭해서 다시 로그인하세요"
│ (입력 폼: username, password)
└─────────────────────────────────────┘

2단계: 공격 URL 생성
┌─────────────────────────────────────┐
│ https://legitimate-site.com/login?next=https://attacker.com/phishing
│
│ 또는
│
│ https://legitimate-site.com/logout?return_to=https://attacker.com/phishing
└─────────────────────────────────────┘

3단계: 사용자가 링크 클릭
┌─────────────────────────────────────┐
│ 사용자: 정상 도메인에서 왔다고 생각
│ (URL 기본 부분이 legitimate-site.com)
│
│ 로그인/로그아웃 완료 후
│ → attacker.com/phishing으로 리다이렉트
└─────────────────────────────────────┘

4단계: 피싱 성공
┌─────────────────────────────────────┐
│ 사용자가 attacker.com의 페이지에서:
│ "Facebook 로그인 재인증"
│
│ 사용자가 다시 입력:
│ username: john@example.com
│ password: secret123
│
│ → 공격자가 정보 탈취
└─────────────────────────────────────┘

5단계: 대규모 공격
┌─────────────────────────────────────┐
│ 공격자가 SNS에서 링크 공유:
│ "당신의 계정이 해킹되었습니다. 여기를 클릭하세요"
│ [링크: legitimate-site.com/login?next=attacker.com/phishing]
│
│ 사용자들이 클릭:
│ → 정상 사이트에서 로그인
│ → 자동으로 attacker.com으로 리다이렉트
│ → 피싱 페이지에서 재입력
└─────────────────────────────────────┘
```

---

### 2. 부분적 검증 (우회 가능)

**우회 가능한 검증 1: 문자열 포함 확인**
```java
@GetMapping("/redirect")
public String redirect(@RequestParam String url) {
    // ❌ 문제: 도메인이 포함되어 있는지만 확인
    if (url.contains("example.com")) {
        return "redirect:" + url;
    }
    throw new IllegalArgumentException("Invalid URL");
}

// 공격자의 우회:
// https://example.com.attacker.com (서브도메인)
// → url.contains("example.com") = true ✅
// → 공격 성공!

// 또는:
// https://attacker.com?domain=example.com
// → url.contains("example.com") = true ✅
// → 공격 성공!
```

**우회 가능한 검증 2: 프로토콜만 확인**
```java
@GetMapping("/redirect")
public String redirect(@RequestParam String url) {
    // ❌ 문제: http/https만 확인
    if (url.startsWith("http://") || url.startsWith("https://")) {
        return "redirect:" + url;
    }
    throw new IllegalArgumentException("Invalid URL");
}

// 공격자의 우회:
// //attacker.com (프로토콜 상대 경로)
// → 시작이 "//"이므로 검증 통과 ✅
// → 공격 성공!

// 또는:
// https://example.com@attacker.com (Basic Auth 문법)
// → startsWith("https://") = true ✅
// → 하지만 실제 호스트는 attacker.com
// → 공격 성공!
```

---

### 3. URL 파싱 함수의 일관성 부족

**문제 있는 코드**
```java
@GetMapping("/redirect")
public String redirect(@RequestParam String url) {
    // ❌ 문제: 검증과 리다이렉트에서 다른 함수 사용
    
    // 검증: String 메서드 사용
    if (url.startsWith("https://example.com")) {
        // 리다이렉트: Spring의 RedirectView 사용 (다르게 파싱)
        return "redirect:" + url;
    }
    throw new IllegalArgumentException("Invalid URL");
}

// URL에 따라 다르게 파싱됨:
String url = "https://example.com%3a.attacker.com";
// String.startsWith() 관점: "https://example.com" (맞음)
// RedirectView 관점: "https://example.com:.attacker.com" (틀림!)
// → 검증은 통과했지만 실제로는 attacker.com으로 이동
```

---

### 4. Java URL 클래스의 함정

**문제 있는 URL 파싱**
```java
@GetMapping("/redirect")
public String redirect(@RequestParam String url) throws Exception {
    // URL 클래스 사용
    URL parsedUrl = new URL(url);
    
    // ❌ 문제: getHost()와 getAuthority()의 차이
    String host = parsedUrl.getHost();
    String authority = parsedUrl.getAuthority();
    
    // 검증
    if (host.equals("example.com")) {
        return "redirect:" + url;
    }
    throw new IllegalArgumentException("Invalid URL");
}

// 다양한 우회 기법:

// 1. URL: https://user:password@attacker.com/
String url = "https://user:password@attacker.com/";
URL parsed = new URL(url);
parsed.getHost();       // "attacker.com"
parsed.getAuthority();  // "user:password@attacker.com"
// → 검증: getHost() != "example.com" (거부됨)
// (이건 사실 안전하긴 함)

// 2. URL: https://example.com@attacker.com/
String url = "https://example.com@attacker.com/";
URL parsed = new URL(url);
parsed.getHost();       // "attacker.com"
parsed.getAuthority();  // "example.com@attacker.com"
// → 검증: getHost() != "example.com" (거부됨)
// (이것도 안전함)

// 3. IPv6 주소 혼동
String url = "https://[::ffff:127.0.0.1]/";
URL parsed = new URL(url);
parsed.getHost();       // "::ffff:127.0.0.1"
// → 127.0.0.1과 다르므로 검증 실패할 수 있음

// 4. 인코딩된 문자
String url = "https://example%2ecom/"; // . 인코딩
URL parsed = new URL(url);
parsed.getHost();       // "example%2ecom" (인코딩된 상태)
// → "example.com"과 맞지 않음 (검증 실패)
// → 하지만 리다이렉트 후 디코딩되면서 example.com으로 파싱될 수 있음
```

---

## ✨ 방어 코드 (After — 공격 원리를 알고 설계한 구현)

### 1. 화이트리스트 기반 검증 (가장 안전)

**Spring Controller (안전한 방식)**
```java
@Controller
@RequestMapping("/auth")
public class AuthController {
    
    @Autowired
    private RedirectUrlValidator urlValidator;
    
    @GetMapping("/login")
    public String login(@RequestParam String username,
                        @RequestParam String password,
                        @RequestParam(required = false) String next,
                        HttpSession session) {
        
        // 로그인 처리
        if (authenticate(username, password)) {
            // ✅ 방어 1: next URL 검증
            String redirectUrl = urlValidator.validateRedirectUrl(next);
            
            // ✅ 방어 2: 세션에 저장 (URL 파라미터 사용 안 함)
            session.setAttribute("originalUrl", redirectUrl);
            
            return "redirect:" + redirectUrl;
        }
        return "redirect:/login?error";
    }
    
    @GetMapping("/logout")
    public String logout(@RequestParam(name = "return_to", required = false) String returnUrl) {
        // 로그아웃 처리
        
        // ✅ 방어: returnUrl 검증
        String validUrl = urlValidator.validateRedirectUrl(returnUrl);
        return "redirect:" + validUrl;
    }
    
    @GetMapping("/oauth-callback")
    public String oauthCallback(@RequestParam String code,
                               @RequestParam(required = false) String state) {
        // OAuth 토큰 교환
        String accessToken = exchangeCodeForToken(code);
        
        // ✅ 방어: state 파라미터에서 원래 URL 가져오기
        String originalUrl = decodeStateParameter(state);
        String redirectUrl = urlValidator.validateRedirectUrl(originalUrl);
        
        return "redirect:" + redirectUrl;
    }
}

// ✅ 화이트리스트 기반 검증 유틸
@Component
public class RedirectUrlValidator {
    
    // ✅ 1단계: 허용할 도메인의 화이트리스트
    private static final Set<String> ALLOWED_DOMAINS = Set.of(
        "example.com",
        "app.example.com",
        "localhost:8080" // 개발 환경
    );
    
    // ✅ 2단계: 허용할 경로의 화이트리스트 (Optional)
    private static final Set<String> ALLOWED_PATHS = Set.of(
        "/dashboard",
        "/profile",
        "/settings",
        "/" // 홈페이지
    );
    
    public String validateRedirectUrl(String url) {
        // 1. 기본값 설정
        if (url == null || url.isEmpty()) {
            return "/dashboard"; // 기본 리다이렉트
        }
        
        try {
            // 2. 상대 URL 처리
            if (!url.startsWith("http://") && !url.startsWith("https://")) {
                // 상대 URL은 자신의 도메인으로 간주
                if (isValidPath(url)) {
                    return url;
                } else {
                    return "/dashboard";
                }
            }
            
            // 3. 절대 URL 검증
            URI uri = new URI(url);
            String host = uri.getHost();
            String port = uri.getPort() == -1 ? "" : ":" + uri.getPort();
            String scheme = uri.getScheme();
            String path = uri.getPath();
            
            // 4. 스킴 검증 (http, https만 허용)
            if (!("http".equals(scheme) || "https".equals(scheme))) {
                return "/dashboard";
            }
            
            // 5. 호스트 검증
            String hostWithPort = (port.isEmpty() ? host : host + port);
            if (!ALLOWED_DOMAINS.contains(hostWithPort)) {
                return "/dashboard";
            }
            
            // 6. 경로 검증 (Optional)
            if (!isValidPath(path)) {
                return "/dashboard";
            }
            
            // 7. URL 정규화 (.. 같은 패턴 제거)
            URL parsedUrl = uri.toURL();
            String normalizedUrl = parsedUrl.toExternalForm();
            
            // 8. 최종 검증 (다시 한 번)
            return normalizedUrl;
            
        } catch (Exception e) {
            // URL 파싱 실패 → 안전하게 기본값 반환
            return "/dashboard";
        }
    }
    
    private boolean isValidPath(String path) {
        if (path == null || path.isEmpty()) {
            return true;
        }
        
        // .. 패턴 차단 (디렉토리 트래버설)
        if (path.contains("..")) {
            return false;
        }
        
        // 쿼리 문자열은 허용 (그대로 전달)
        // fragment는 서버에서 무시되지만 체크
        
        // 경로 화이트리스트 확인 (선택사항)
        String pathOnly = path.split("\\?")[0]; // 쿼리 제거
        return ALLOWED_PATHS.isEmpty() || ALLOWED_PATHS.contains(pathOnly);
    }
}
```

---

### 2. 상대 URL 사용 (가장 간단)

**가장 안전한 방식**
```java
@Controller
@RequestMapping("/auth")
public class AuthController {
    
    @PostMapping("/login")
    public String login(@RequestParam String username,
                        @RequestParam String password,
                        @RequestParam(required = false) String next) {
        
        // 로그인 처리
        if (authenticate(username, password)) {
            // ✅ 방어: 상대 URL만 허용
            // 절대 URL은 무시하고 기본값 사용
            
            if (next != null && next.startsWith("/")) {
                // 상대 URL: /dashboard, /profile 등
                // 자신의 도메인이라고 보장됨
                return "redirect:" + next;
            } else {
                // 절대 URL이거나 다른 도메인: 무시
                return "redirect:/dashboard";
            }
        }
        return "redirect:/login?error";
    }
}
```

---

### 3. 안전한 상태 전달 (OAuth 2.0)

**OAuth 콜백 처리**
```java
@Controller
@RequestMapping("/oauth")
public class OAuthController {
    
    @Autowired
    private RedirectUrlValidator urlValidator;
    @Autowired
    private StateEncryptor stateEncryptor;
    
    @GetMapping("/authorize")
    public String authorize(@RequestParam(required = false) String returnUrl) {
        // ✅ 1단계: returnUrl 검증
        String validUrl = urlValidator.validateRedirectUrl(returnUrl);
        
        // ✅ 2단계: state 파라미터에 암호화해서 저장
        String state = stateEncryptor.encryptUrl(validUrl);
        
        // ✅ 3단계: OAuth 제공자로 리다이렉트
        String oauthUrl = "https://oauth-provider.com/authorize?" +
            "client_id=" + CLIENT_ID +
            "&redirect_uri=" + urlEncode(CALLBACK_URL) +
            "&state=" + state; // state에 returnUrl 포함
        
        return "redirect:" + oauthUrl;
    }
    
    @GetMapping("/callback")
    public String callback(@RequestParam String code,
                          @RequestParam String state) {
        try {
            // ✅ 4단계: state 파라미터에서 원래 URL 복원
            String returnUrl = stateEncryptor.decryptUrl(state);
            
            // ✅ 5단계: 다시 한 번 검증 (방어 깊이)
            String validUrl = urlValidator.validateRedirectUrl(returnUrl);
            
            // OAuth 토큰 교환
            String accessToken = exchangeCodeForToken(code);
            
            // ✅ 6단계: 검증된 URL로만 리다이렉트
            return "redirect:" + validUrl;
            
        } catch (Exception e) {
            // state 파라미터 복호화 실패 → 안전하게 기본값
            return "redirect:/dashboard";
        }
    }
}

// ✅ State 파라미터 암호화
@Component
public class StateEncryptor {
    
    @Value("${security.encryption-key}")
    private String encryptionKey;
    
    public String encryptUrl(String url) {
        // AES 암호화
        String encrypted = AES.encrypt(url, encryptionKey);
        return Base64.encode(encrypted);
    }
    
    public String decryptUrl(String state) {
        // Base64 디코딩 후 AES 복호화
        String encrypted = Base64.decode(state);
        return AES.decrypt(encrypted, encryptionKey);
    }
}
```

---

### 4. Spring Security의 기본 설정

**Spring Security SavedRequestAwareAuthenticationSuccessHandler**
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/public/**").permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .loginProcessingUrl("/login")
                // ✅ 기본 설정: SavedRequestAwareAuthenticationSuccessHandler
                // (로그인 전 접근하려던 페이지로 리다이렉트)
                .successHandler(authenticationSuccessHandler())
            );
        
        return http.build();
    }
    
    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        // ✅ Spring Security 기본 Handler
        // 자동으로 요청한 원본 페이지로 리다이렉트
        // (화이트리스트 검증 내장)
        SavedRequestAwareAuthenticationSuccessHandler handler = 
            new SavedRequestAwareAuthenticationSuccessHandler();
        handler.setDefaultTargetUrl("/dashboard");
        return handler;
    }
}
```

---

### 5. 커스텀 AuthenticationSuccessHandler

**안전한 리다이렉트 핸들러**
```java
@Component
public class SafeAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    
    @Autowired
    private RedirectUrlValidator urlValidator;
    
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                       HttpServletResponse response,
                                       Authentication authentication)
            throws IOException, ServletException {
        
        // ✅ 1단계: 요청한 원본 URL 가져오기
        SavedRequest savedRequest = 
            WebUtils.getAndDeleteSessionAttribute(request, "SPRING_SECURITY_SAVED_REQUEST_KEY");
        
        String targetUrl = "/dashboard"; // 기본값
        
        if (savedRequest != null) {
            // ✅ 2단계: SavedRequest의 URL 검증
            targetUrl = urlValidator.validateRedirectUrl(savedRequest.getRedirectUrl());
        } else {
            // 쿠키나 세션에서 returnUrl 확인
            String returnUrl = request.getParameter("return_to");
            if (returnUrl != null) {
                targetUrl = urlValidator.validateRedirectUrl(returnUrl);
            }
        }
        
        // ✅ 3단계: 검증된 URL로만 리다이렉트
        response.sendRedirect(targetUrl);
    }
}
```

---

## 🔬 공격 원리 분석 (공격자 관점의 내부 동작)

### Open Redirect 공격 시나리오

```
1단계: 공격 URL 생성
┌─────────────────────────────────────┐
│ 정상 도메인:
│ https://login.company.com/login?next=https://attacker.com/phishing
│
│ 또는 더 은폐된 형태:
│ https://login.company.com/login?next=//attacker.com/
│ https://login.company.com/logout?return_to=attacker.com
│ https://login.company.com/oauth/callback?state=...&redirect_uri=attacker.com
└─────────────────────────────────────┘

2단계: 소셜 엔지니어링
┌─────────────────────────────────────┐
│ 공격자가 SNS/이메일로 전파:
│ "Your account has expired. Click here to re-authenticate:"
│ [링크: login.company.com/login?next=attacker.com]
│
│ 사용자 관점:
│ - URL이 login.company.com에서 시작
│ - 정상 사이트라고 생각
│ - 클릭!
└─────────────────────────────────────┘

3단계: 정상 사이트에서 로그인
┌─────────────────────────────────────┐
│ 사용자가 정상 로그인 페이지 봄
│ (HTTPS, 정상 도메인)
│
│ 로그인 정보 입력:
│ username: user@example.com
│ password: actualpassword123
│
│ 로그인 성공 후 자동으로 리다이렉트
│ → attacker.com (검증 없이)
└─────────────────────────────────────┘

4단계: 피싱 페이지
┌─────────────────────────────────────┐
│ attacker.com/phishing에서:
│ "Session expired. Please re-login:"
│
│ 사용자가 다시 입력:
│ username: user@example.com
│ password: actualpassword123 (다시 입력)
│
│ → 공격자가 정보 탈취!
└─────────────────────────────────────┘

5단계: 신뢰도 악용
┌─────────────────────────────────────┐
│ 사용자가 생각하는 것:
│ "정상 사이트 → 로그인 → 내 계정 관리 페이지"
│
│ 실제 일어난 것:
│ "정상 사이트 → 로그인 → 공격자 피싱 사이트"
│
│ 문제점:
│ - 정상 사이트가 공격자 사이트로 자신을 리다이렉트
│ - 신뢰도가 높아서 피싱 성공률 매우 높음
│ - 사용자가 의심하지 않음
└─────────────────────────────────────┘
```

### URL 파싱 차이로 인한 우회

```
공격자의 관점:

1. 문자열 기반 검증 우회
┌─────────────────────────────────────┐
│ 검증: url.contains("company.com")
│
│ 공격 URL:
│ https://company.com.attacker.com
│ → contains("company.com") = true ✅
│ → 검증 통과, 리다이렉트됨
│
│ 결과: attacker.com으로 이동 ❌
└─────────────────────────────────────┘

2. 프로토콜 상대 경로 우회
┌─────────────────────────────────────┐
│ 검증: url.startsWith("https://")
│
│ 공격 URL:
│ //attacker.com
│ → startsWith("https://") = false ❌
│
│ 하지만 다른 검증에서 통과:
│ if (!url.startsWith("javascript:")) { // 통과!
│     return "redirect:" + url;
│ }
│
│ 결과: //attacker.com으로 리다이렉트
│ 브라우저가 현재 프로토콜 유지하면서 attacker.com으로 이동 ❌
└─────────────────────────────────────┘

3. 인코딩 우회
┌─────────────────────────────────────┐
│ 검증: url.equals("https://company.com")
│
│ 공격 URL (인코딩된):
│ https://attacker.com%3fcompany.com (? 인코딩)
│ → equals() = false ❌
│
│ 하지만 리다이렉트 후:
│ 브라우저가 디코딩:
│ https://attacker.com?company.com
│ → attacker.com으로 이동 ❌
└─────────────────────────────────────┘

4. URL 파싱 함수 불일치
┌─────────────────────────────────────┐
│ 검증: new URL(url).getHost() == "company.com"
│
│ 공격 URL:
│ https://company.com@attacker.com
│ getHost() = "attacker.com" (@ 뒤)
│ → 검증 실패 ❌ (이건 안전)
│
│ 더 나쁜 공격:
│ https://attacker.com?url=https://company.com
│ getHost() = "attacker.com"
│ → 검증 실패 ❌ (이것도 안전)
│
│ 취약한 검증 예:
│ if (url.contains(":company.com")) { // 포함 확인
│ getHost() 검증과 다름!
│ → 우회 가능
└─────────────────────────────────────┘
```

---

## 💻 실전 실험 (취약점 재현 → 공격 → 방어 검증)

### 실험 1: Open Redirect 재현

**Step 1: 취약한 엔드포인트**
```java
@GetMapping("/redirect")
public String redirect(@RequestParam String url) {
    // ❌ 검증 없음
    return "redirect:" + url;
}

// localhost:8080/redirect?url=https://attacker.com
// → attacker.com으로 리다이렉트됨 ❌
```

**Step 2: 공격 URL**
```
http://localhost:8080/redirect?url=https://evil.com/phishing

사용자가 클릭:
1. localhost:8080/redirect?url=... 로드
2. 서버가 302 응답
3. Location: https://evil.com/phishing
4. 브라우저가 evil.com으로 이동 ❌
```

**Step 3: 방어 적용**
```java
@GetMapping("/redirect")
public String redirect(@RequestParam String url) {
    // ✅ 방어: 화이트리스트 검증
    String validUrl = urlValidator.validateRedirectUrl(url);
    return "redirect:" + validUrl;
}

// localhost:8080/redirect?url=https://attacker.com
// → urlValidator가 attacker.com 거부
// → 기본값 "/dashboard"로 리다이렉트 ✅

// localhost:8080/redirect?url=/dashboard
// → 상대 URL 허용
// → /dashboard로 리다이렉트 ✅
```

**Step 4: 우회 시도**
```bash
# 다양한 우회 기법 테스트

# 1. 프로토콜 상대 경로
http://localhost:8080/redirect?url=//attacker.com
# → 검증 실패, 기본값으로 리다이렉트 ✅

# 2. Base64 인코딩
http://localhost:8080/redirect?url=aHR0cHM6Ly9hdHRhY2tlci5jb20=
# → URL로 디코딩 안 됨, 기본값으로 리다이렉트 ✅

# 3. 이스케이프 문자
http://localhost:8080/redirect?url=https://attacker.com%00.example.com
# → URI 파싱 시 %00 이후 제거 가능하지만,
# → 전체 URL이 attacker.com을 포함하므로 거부 ✅

# 4. 대문자 프로토콜
http://localhost:8080/redirect?url=HTTPS://attacker.com
# → URI 파싱이 정규화 (소문자 변환)
# → attacker.com 인식, 거부 ✅
```

---

### 실험 2: 다양한 검증 방식 비교

**Step 1: 안전하지 않은 검증들**
```bash
# Test Case 1: url.contains("example.com")
# 공격: https://example.com.attacker.com
# 결과: 통과 ❌

# Test Case 2: url.startsWith("http")
# 공격: //attacker.com
# 결과: 통과 ❌

# Test Case 3: url.startsWith("https://example.com")
# 공격: https://example.com@attacker.com
# 결과: 통과 (파싱하면 attacker.com이 실제 호스트) ❌
```

**Step 2: 안전한 검증**
```bash
# 화이트리스트 검증
# URI uri = new URI(url);
# String host = uri.getHost();
# if (!ALLOWED_HOSTS.contains(host)) { throw new Exception(); }

# Test Case 1: https://example.com.attacker.com
# getHost() = "example.com.attacker.com"
# NOT in ALLOWED_HOSTS → 거부 ✅

# Test Case 2: //attacker.com
# URI 파싱 실패 (상대 경로) → 거부 ✅

# Test Case 3: https://example.com@attacker.com
# getHost() = "attacker.com"
# NOT in ALLOWED_HOSTS → 거부 ✅
```

---

### 실험 3: Spring Security SavedRequest

**Step 1: 정상 흐름**
```
1. 사용자가 /secure 접속
   → 로그인 필수, /login으로 리다이렉트
   
2. Spring Security가 SavedRequest 생성
   (원래 요청한 /secure 정보 저장)
   
3. 로그인 성공 후
   → SavedRequest의 URL로 자동 리다이렉트
   → /secure로 이동
```

**Step 2: 코드 검증**
```java
// Spring Security 기본 동작
SavedRequestAwareAuthenticationSuccessHandler handler = 
    new SavedRequestAwareAuthenticationSuccessHandler();

// /secure에 접속했을 때만 SavedRequest 생성
// 다른 도메인의 redirect_uri 파라미터는 무시됨 ✅

// 따라서:
// https://app.company.com/secure → SavedRequest 생성
// 로그인 후 /secure로 리다이렉트 ✅
//
// 다른 도메인의 redirect_uri → 무시됨
// 로그인 후 기본값으로 리다이렉트 ✅
```

---

## 📊 공격 성공 조건 vs 방어 성공 조건 비교

| 구분 | 공격 성공 조건 | 방어 성공 조건 |
|------|---|---|
| **검증 없음** | 모든 URL 허용 | 화이트리스트 기반 검증 |
| **부분 검증** | contains, startsWith 등 우회 가능 | URI 파싱 후 getHost() 검증 |
| **절대 URL** | http://, https:// 모두 허용 | 허용 도메인만 명시적으로 등록 |
| **상대 URL** | //, javascript: 등 허용 | 상대 경로(/)만 허용 |
| **프로토콜** | 모든 프로토콜 허용 | http, https만 허용 |
| **파라미터** | URL에 쿼리 포함 | 쿼리는 허용하되 주요 부분만 검증 |

---

## ⚖️ 트레이드오프 (보안 강화 vs 사용성/성능)

### 1. 화이트리스트 범위

**매우 엄격 (보안 우선)**
```
ALLOWED_DOMAINS = {"example.com"}

장점:
- 공격 거의 불가능
- 명확한 정책

단점:
- 새 도메인 추가할 때마다 코드 수정
- 동적 서브도메인 지원 불가능 (cdn.example.com, api.example.com)
- 개발 서버 따로 설정 필요
```

**덜 엄격하지만 합리적**
```
ALLOWED_DOMAINS = {"*.example.com", "app.example.com"}

장점:
- 동적 서브도메인 지원
- 더 유연함

단점:
- 정규식 기반이면 성능 영향
- "*.example.com"은 여전히 test.evil.com 같은 신규 서브도메인 포함
- 매칭 로직이 더 복잡
```

### 2. 상대 URL vs 절대 URL

**상대 URL만 허용 (가장 안전)**
```java
if (next != null && next.startsWith("/")) {
    return "redirect:" + next;
}
```

장점: 같은 도메인만 가능, 간단함
단점: 다른 도메인으로의 의도적 리다이렉트 불가능 (거의 필요 없음)

### 3. 검증 시점

**요청 시점에만 검증 (현재 방식)**
```
사용자 클릭 → 요청 → 서버 검증 → 리다이렉트
```

장점: 매번 검증, 안전
단점: 약간의 지연

**사전에 URL 등록**
```
관리자가 미리 허용 URL 등록 → 사용자는 인덱스로만 참조
```

장점: 빠름, 명확함
단점: 유연성 부족

---

## 📌 핵심 정리

### Open Redirect 방어의 3단계

```
1단계: 절대 URL은 화이트리스트 검증
Set<String> allowedDomains = {"example.com", "app.example.com"};
if (uri.getHost() not in allowedDomains) {
    return "/dashboard";
}

2단계: 상대 URL은 "/"로 시작하는지만 확인
if (url.startsWith("/")) {
    return "redirect:" + url;
}

3단계: OAuth는 state 파라미터에 URL 암호화
// 로그인 전: state = encrypt(returnUrl)
// 콜백 후: returnUrl = decrypt(state)
```

### 검증 구현 체크리스트

```
✅ URI 클래스 사용 (String 메서드 대신)
✅ getHost() 메서드로 호스트명 추출
✅ 호스트명을 화이트리스트와 비교
✅ 상대 URL은 "/"로 시작하는지만 확인
✅ 프로토콜은 http, https만 허용
✅ 예외 발생 시 기본값 반환
✅ 로그 남기기 (의심스러운 리다이렉트 시도)
```

---

## 🤔 생각해볼 문제 (+ 해설)

### Q1. URL 쿼리 파라미터에 이동할 도메인을 넣으면 우회 가능한가?

**예시**
```
https://example.com?next=attacker.com
```

**해설**
```
아니다, 안전하다.

URI 파싱:
url = "https://example.com?next=attacker.com"
uri = new URI(url)
uri.getHost()  // "example.com" (쿼리는 포함 안 됨)
uri.getPath()  // "/"
uri.getQuery() // "next=attacker.com"

호스트 검증:
"example.com" in ALLOWED_HOSTS → 통과 ✅

결과:
next 파라미터는 서버에서만 볼 수 있음
브라우저는 쿼리를 무시하고 호스트로만 연결
→ example.com으로 접속됨 ✅

하지만 주의:
next 파라미터를 다시 사용해서 리다이렉트하면:
GET /example.com?next=attacker.com
→ 서버가 next=attacker.com을 읽고
→ redirect:attacker.com 실행
→ 위험! ❌

따라서 next 파라미터도 검증해야 함:
String next = request.getParameter("next");
String validNext = urlValidator.validateRedirectUrl(next);
return "redirect:" + validNext;
```

---

### Q2. 로컬호스트나 127.0.0.1은 안전한가?

**해설**
```
일반적인 상황:
localhost:8080, 127.0.0.1:8080은 개발/테스트 환경
프로덕션 환경에선 example.com 같은 도메인 사용

하지만 특수 경우:

위험: 내부 네트워크에서의 공격
```
ALLOWED_DOMAINS = {"example.com", "localhost:8080"}
```

공격자가 내부 네트워크에 접근했다면:
http://localhost:8080/redirect?url=http://internal-admin-panel:8080
→ 내부 시스템 접근 가능

권장:
- 프로덕션: 정확한 도메인만 등록
- 개발: localhost는 따로 설정 (환경 변수)
```
if (isProd()) {
    allowedDomains.add("example.com");
} else {
    allowedDomains.add("localhost:8080");
}
```
```

---

### Q3. IPv6 주소 리다이렉트는 안전한가?

**해설**
```
IPv6 주소 예시:
::1 (로컬호스트)
2001:db8::1 (정상 주소)
::ffff:127.0.0.1 (IPv4를 IPv6로 매핑)

문제점:
```
ALLOWED_DOMAINS = {"127.0.0.1"}
```

공격:
url = "http://::1/" (IPv6 로컬호스트)
uri.getHost()  // "::1"
"::1" in ALLOWED_DOMAINS → false ❌

두 주소가 같은데도 거부됨!

또는:
url = "http://[::1]/" (IPv6는 괄호 필요)
uri.getHost() // "::1" (괄호 제거됨)
같은 문제

권장:
IPv6 정규화:
```java
String host = uri.getHost();
String normalized = InetAddress.getByName(host).getHostAddress();
if (ALLOWED_ADDRESSES.contains(normalized)) { // IP 주소로 비교
    return url;
}
```

또는 URI 객체 직접 비교:
```java
URI allowedUri = new URI("http://127.0.0.1");
URI requestUri = new URI(url);
if (allowedUri.getHost().equals(requestUri.getHost())) {
    return url;
}
```

하지만 더 안전한 방법:
- IP 주소로 리다이렉트하지 않기 (도메인명 사용)
- 화이트리스트에 도메인 사용
```

---

### Q4. 프래그먼트(#)가 있는 URL은 안전한가?

**해설**
```
URL 구조:
https://example.com/page#section?dangerous=data

프래그먼트(#):
- 브라우저에서만 처리됨
- 서버로 전송되지 않음
- URL 앞부분만 서버에 전달

예시:
```
https://example.com/redirect?url=https://attacker.com#innocent
```

서버가 받는 요청:
GET /redirect?url=https://attacker.com HTTP/1.1
(#innocent 부분은 전송 안 됨)

검증:
uri = new URI("https://example.com/redirect?url=https://attacker.com#innocent")
uri.getHost() // "example.com"
uri.getQuery() // "url=https://attacker.com"

결론:
프래그먼트는 서버에서 무시되므로 안전 ✅

하지만 주의:
JavaScript에서 location.hash를 사용하면:
window.location.hash = "#https://attacker.com"
→ 클라이언트 사이드 리다이렉트 가능 (다른 문제)
```

---

### Q5. OAuth의 state 파라미터가 충분한 보호인가?

**해설**
```
state 파라미터의 목적:
1. CSRF 방지 (토큰으로 검증)
2. 트랜잭션 상태 유지 (encrypt/decrypt로 원본 URL 보호)

흐름:
```
1. 사용자가 /login?return_to=/profile 방문
2. state = encrypt("/profile")
3. OAuth 제공자로 리다이렉트 (state 포함)
4. OAuth 제공자가 콜백: /callback?code=...&state=...
5. state 복호화 → "/profile" 획득
6. 검증 후 리다이렉트 → /profile

장점:
- 원본 URL이 사용자 브라우저에 노출 안 됨
- 공격자가 state 파라미터 조작 불가능 (암호화됨)

단점:
- 암호화 키 관리 필요
- 암호화/복호화 오버헤드

올바른 구현:
```java
// 1. 암호화 키 보안
@Value("${security.state-key}")
private String stateEncryptionKey; // 환경 변수에서 로드

// 2. 안전한 암호화 (AES 사용)
public String encryptState(String returnUrl) {
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
    byte[] encrypted = cipher.doFinal(returnUrl.getBytes());
    return Base64.getEncoder().encodeToString(encrypted);
}

// 3. 검증된 복호화
public String decryptState(String state) {
    try {
        byte[] encrypted = Base64.getDecoder().decode(state);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
        String decrypted = new String(cipher.doFinal(encrypted));
        
        // 복호화된 URL도 다시 검증
        return urlValidator.validateRedirectUrl(decrypted);
    } catch (Exception e) {
        return "/dashboard"; // 복호화 실패 → 안전하게 기본값
    }
}
```

결론:
state 파라미터 + URL 검증 조합이 최선 ✅
```

<div align="center">

**[⬅️ 이전: 보안 HTTP 헤더 완전 가이드](./05-security-http-headers.md)** | **[홈으로 🏠](../README.md)** | **[다음: Chapter 5 — IDOR 공격과 소유권 검증 ➡️](../access-control/01-idor-ownership-check.md)**

</div>
