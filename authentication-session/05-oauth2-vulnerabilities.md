# OAuth2 취약점 (Authorization Code Flow)
---

## 🎯 핵심 질문
OAuth2의 Authorization Code Flow는 세계에서 가장 널리 사용되는 인증 프로토콜이다. 하지만 state 파라미터가 없거나, 오픈 리다이렉트 취약점이 있거나, PKCE가 없으면 어떻게 공격자가 Authorization Code를 탈취할 수 있는가?

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

### Instagram CSRF 사건 (2012)
Instagram은 "Login with Facebook" 기능을 제공했는데, state 파라미터가 없었다:
1. 공격자가 Facebook 로그인 후 Authorization Code 획득
2. 공격자가 피해자에게 다음 링크 전송: `instagram.com/callback?code=attacker_code`
3. 피해자가 링크 클릭
4. 피해자 계정이 공격자의 Facebook에 연결됨
5. 공격자가 피해자 계정 제어

### Twitter OAuth CSRF (2010)
Twitter도 비슷한 취약점이 있었다. 공격자는:
1. Twitter와 애플리케이션을 연동
2. Authorization Code 얻음
3. 피해자의 계정에 강제로 같은 Authorization Code 사용
4. 피해자 계정을 공격자의 애플리케이션에 연결

### Google의 PKCE 권장 (2020년대)
Google은 모든 모바일 앱과 SPA에서 PKCE를 필수로 요구하기 시작했다. 왜? Public Client에서:
1. Authorization Code가 브라우저에 노출됨
2. PKCE 없으면 누구나 Authorization Code로 토큰 교환 가능
3. Public Client를 가장한 공격자가 토큰 탈취

### 오픈 리다이렉트 합작 공격
Dropbox에서 발견된 사례:
1. OAuth 리다이렉트 URI가 사용자 입력을 그대로 사용
2. 공격자: `https://dropbox.com/oauth?redirect_uri=attacker.com/phishing`
3. 사용자가 로그인 후 attacker.com으로 리다이렉트
4. attacker.com이 Authorization Code로 가짜 로그인 폼 표시
5. 사용자가 추가로 비밀번호 입력 (2FA 우회)

## 😱 취약한 코드 (Before — 원리를 모를 때의 구현)

### 1. state 파라미터 없는 Authorization Code Flow

```java
// ❌ 취약한 코드: state 파라미터 없음
@RestController
public class VulnerableOAuth2Controller {
    
    @GetMapping("/login/oauth2/authorization/google")
    public String initiateLogin() {
        // ❌ state 파라미터 없음
        String authorizationUrl = "https://accounts.google.com/o/oauth2/v2/auth" +
            "?client_id=" + clientId +
            "&redirect_uri=" + redirectUri +
            "&scope=openid+email+profile" +
            "&response_type=code";
        
        return "redirect:" + authorizationUrl;
    }
    
    @GetMapping("/login/oauth2/callback/google")
    public String handleCallback(
            @RequestParam String code,
            @RequestParam(required = false) String state) {
        
        // ❌ state 파라미터 검증 안함
        // 공격자가 자신의 Authorization Code를 피해자에게 주입 가능
        
        // Authorization Code를 토큰으로 교환
        String accessToken = exchangeCodeForToken(code);
        
        // 사용자 정보 조회
        UserInfo userInfo = getUserInfo(accessToken);
        
        // 로그인 처리
        return "redirect:/home";
    }
}

// 공격 시나리오
// 1. 공격자가 자신의 구글 계정으로 로그인
//    Authorization Code: attacker_code_abc123
//
// 2. 공격자가 피해자에게 다음 링크 전송
//    https://app.com/login/oauth2/callback/google?code=attacker_code_abc123
//
// 3. 피해자가 링크 클릭
//    서버가 code=attacker_code_abc123으로 토큰 교환
//
// 4. 피해자 계정이 공격자의 Google 계정과 연결됨
//    결과: 공격자가 피해자 계정 제어
```

### 2. PKCE 없는 Public Client

```java
// ❌ 취약한 코드: PKCE 없음
@Component
public class VulnerablePublicClientOAuth2 {
    
    // 모바일 앱의 OAuth2 로그인
    public void initiateLogin(Context context) {
        // ❌ PKCE 없음
        String authorizationUrl = "https://accounts.google.com/o/oauth2/v2/auth" +
            "?client_id=" + clientId +
            "&redirect_uri=" + redirectUri +
            "&scope=openid+email" +
            "&response_type=code";
        
        // 브라우저 열기
        Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(authorizationUrl));
        context.startActivity(intent);
    }
    
    public void handleAuthorizationCode(String code) {
        // ❌ 바로 토큰 교환
        String accessToken = exchangeCodeForToken(code);
        
        // 문제: Authorization Code가 브라우저에 노출됨
        // - 다른 앱이 같은 redirect_uri를 등록하면?
        // - 공격자 앱이 Authorization Code 탈취 가능
        // - PKCE 없으면 공격자도 토큰 교환 가능
    }
}

// 공격 시나리오 (PKCE 없을 때)
// 1. 정상 앱: Authorization Code 받음
//    code=legit_code_xyz
//
// 2. 공격 앱이 같은 redirect_uri로 등록
//    (또는 URI 매칭 규칙을 악용)
//
// 3. OS가 Authorization Code를 공격 앱으로 보냄
//    Intent: scheme://redirect_uri?code=legit_code_xyz
//
// 4. 공격자가 Authorization Code 획득
//    POST /token
//    grant_type=authorization_code
//    code=legit_code_xyz
//    client_id=attacker_client_id
//
// 5. ❌ PKCE 없으면 code_verifier 검증 안함
//    → 공격자가 토큰 획득 가능!
//
// 6. 공격자가 피해자 계정 제어
```

### 3. 오픈 리다이렉트 취약점

```java
// ❌ 취약한 코드: redirect_uri 검증 부족
@Configuration
public class VulnerableOAuth2Config {
    
    @Bean
    public ClientRegistration googleClientRegistration() {
        return ClientRegistration.withRegistrationId("google")
            .clientId(clientId)
            .clientSecret(clientSecret)
            // ❌ redirect_uri가 동적으로 설정됨
            .redirectUri("{baseUrl}/login/oauth2/callback/{registrationId}")
            .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
            .tokenUri("https://www.googleapis.com/oauth2/v4/token")
            .userInfoUri("https://www.googleapis.com/oauth2/v1/userinfo")
            .build();
    }
}

// 공격 시나리오
// 1. 등록된 redirect_uri: https://app.com/login/oauth2/callback/google
//
// 2. 서버가 redirect_uri 검증할 때
//    사용자 입력을 포함하면:
//    if (userProvidedUri.startsWith(registeredUri)) {
//        // ❌ https://app.com/login/oauth2/callback/google.attacker.com도 매칭됨!
//    }
//
// 3. 공격자가 다음 URL 제작
//    https://accounts.google.com/o/oauth2/v2/auth
//    ?client_id=legitimate_client_id
//    &redirect_uri=https://app.com/login/oauth2/callback/google@attacker.com
//    (@ 사용으로 호스트명 변조)
//
// 4. 또는
//    &redirect_uri=https://app.com.attacker.com/login/oauth2/callback/google
//    (서브도메인 악용)
//
// 5. 사용자가 로그인 후
//    Authorization Code가 attacker.com으로 리다이렉트됨
//
// 6. 공격자가 Authorization Code + code를 획득
//    → 토큰 교환 가능

// ❌ 더 취약한 경우: redirect_uri가 매개변수로 받아짐
@GetMapping("/oauth2/init")
public String initOAuth2(@RequestParam String redirectUri) {
    // ❌ 사용자 입력을 그대로 사용
    String authUrl = googleAuthUrl + 
        "&redirect_uri=" + URLEncoder.encode(redirectUri, "UTF-8");
    return "redirect:" + authUrl;
}
```

## ✨ 방어 코드 (After — 공격 원리를 알고 설계한 구현)

### 1. state 파라미터 기반 CSRF 방어

```java
// ✅ 안전한 코드: state 파라미터 포함
@Service
public class SecureOAuth2Service {
    
    @Autowired
    private RedisTemplate<String, String> redisTemplate;
    
    private static final String STATE_PREFIX = "oauth2_state:";
    private static final long STATE_EXPIRY_SECONDS = 600;  // 10분
    
    // Authorization 요청 시 state 생성
    public String generateAuthorizationUrl(HttpSession session) {
        // ✅ 1. 강력한 랜덤 state 생성
        String state = UUID.randomUUID().toString();
        
        // ✅ 2. state를 Redis에 저장 (만료 시간 설정)
        String sessionId = session.getId();
        redisTemplate.opsForValue().set(
            STATE_PREFIX + sessionId,
            state,
            STATE_EXPIRY_SECONDS,
            TimeUnit.SECONDS
        );
        
        // ✅ 3. Authorization URL 생성
        String authorizationUrl = "https://accounts.google.com/o/oauth2/v2/auth" +
            "?client_id=" + clientId +
            "&redirect_uri=" + URLEncoder.encode(redirectUri, "UTF-8") +
            "&scope=openid+email+profile" +
            "&response_type=code" +
            "&state=" + state;  // ← state 포함
        
        return authorizationUrl;
    }
    
    // Callback 처리 시 state 검증
    public UserInfo handleAuthorizationCallback(
            HttpSession session,
            @RequestParam String code,
            @RequestParam String state) {
        
        // ✅ 1. Redis에서 저장된 state 조회
        String sessionId = session.getId();
        String savedState = redisTemplate.opsForValue()
            .get(STATE_PREFIX + sessionId);
        
        // ✅ 2. state 검증 (일치하지 않으면 CSRF 공격)
        if (savedState == null || !savedState.equals(state)) {
            throw new SecurityException("CSRF 공격 감지: state 파라미터 불일치");
        }
        
        // ✅ 3. state 사용 후 삭제 (일회용)
        redisTemplate.delete(STATE_PREFIX + sessionId);
        
        // ✅ 4. Authorization Code로 토큰 교환
        String accessToken = exchangeCodeForToken(code);
        
        // ✅ 5. 사용자 정보 조회
        UserInfo userInfo = getUserInfo(accessToken);
        
        return userInfo;
    }
}

// Spring Security OAuth2 설정에서 자동 처리
@Configuration
public class OAuth2SecurityConfig {
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .oauth2Login(oauth2 -> oauth2
                // ✅ Spring Security가 자동으로 state 생성 및 검증
                // (기본값: RandomStateOAuth2AuthorizationRequestResolver)
                .authorizationEndpoint(authEndpoint -> authEndpoint
                    .authorizationRequestResolver(
                        new DefaultOAuth2AuthorizationRequestResolver(
                            clientRegistrationRepository,
                            "/oauth2/authorization"
                        )
                    )
                )
                .userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint
                    .userService(oauth2UserService())
                )
            )
            .build();
        
        return http.build();
    }
}

// Callback 엔드포인트 (Spring Security가 자동 처리)
@RestController
public class OAuth2CallbackController {
    
    @GetMapping("/login/oauth2/callback/{registrationId}")
    public String oauth2Callback(@PathVariable String registrationId) {
        // ✅ Spring Security가 자동으로 state 검증 후 인증
        // 개발자는 별도 처리 불필요
        return "redirect:/home";
    }
}
```

### 2. PKCE (Proof Key for Code Exchange) 구현

```java
// ✅ 안전한 코드: PKCE 포함
@Service
public class PKCEOAuth2Service {
    
    @Autowired
    private RedisTemplate<String, String> redisTemplate;
    
    private static final String CODE_VERIFIER_PREFIX = "pkce_verifier:";
    private static final long CODE_VERIFIER_EXPIRY = 600;  // 10분
    
    // PKCE: code_challenge 생성
    public PKCEChallenge generatePKCEChallenge(HttpSession session) {
        // ✅ 1. code_verifier 생성 (43-128자의 unreserved 문자)
        String codeVerifier = generateCodeVerifier();
        
        // ✅ 2. code_challenge 생성 (S256: SHA-256)
        String codeChallenge = generateCodeChallenge(codeVerifier);
        
        // ✅ 3. code_verifier를 Redis에 저장
        String sessionId = session.getId();
        redisTemplate.opsForValue().set(
            CODE_VERIFIER_PREFIX + sessionId,
            codeVerifier,
            CODE_VERIFIER_EXPIRY,
            TimeUnit.SECONDS
        );
        
        return new PKCEChallenge(codeChallenge, "S256");
    }
    
    // code_verifier 생성
    private String generateCodeVerifier() {
        // 43-128자, unreserved 문자만 사용: [A-Z] [a-z] [0-9] - . _ ~
        SecureRandom random = new SecureRandom();
        StringBuilder verifier = new StringBuilder();
        
        for (int i = 0; i < 128; i++) {
            int index = random.nextInt(66);  // 66개의 unreserved 문자
            String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
            verifier.append(chars.charAt(index));
        }
        
        return verifier.toString();
    }
    
    // code_challenge 생성 (S256)
    private String generateCodeChallenge(String codeVerifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
            
            // Base64 URL-safe encoding (padding 제거)
            String challenge = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(hash);
            
            return challenge;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 알고리즘 불가능", e);
        }
    }
    
    // Authorization URL 생성 (PKCE 포함)
    public String generateAuthorizationUrlWithPKCE(HttpSession session) {
        PKCEChallenge challenge = generatePKCEChallenge(session);
        
        String authorizationUrl = "https://accounts.google.com/o/oauth2/v2/auth" +
            "?client_id=" + clientId +
            "&redirect_uri=" + URLEncoder.encode(redirectUri, "UTF-8") +
            "&scope=openid+email+profile" +
            "&response_type=code" +
            "&code_challenge=" + challenge.codeChallenge +
            "&code_challenge_method=" + challenge.method;  // ← PKCE 파라미터
        
        return authorizationUrl;
    }
    
    // Token 교환 시 code_verifier 검증
    public String exchangeCodeForTokenWithPKCE(
            HttpSession session,
            String code) {
        
        // ✅ 1. Redis에서 code_verifier 조회
        String sessionId = session.getId();
        String codeVerifier = redisTemplate.opsForValue()
            .get(CODE_VERIFIER_PREFIX + sessionId);
        
        if (codeVerifier == null) {
            throw new SecurityException("PKCE code_verifier를 찾을 수 없습니다");
        }
        
        // ✅ 2. code_verifier를 포함한 토큰 요청
        String tokenResponse = restTemplate.postForObject(
            "https://www.googleapis.com/oauth2/v4/token",
            Map.of(
                "grant_type", "authorization_code",
                "code", code,
                "client_id", clientId,
                "client_secret", clientSecret,
                "redirect_uri", redirectUri,
                "code_verifier", codeVerifier  // ← PKCE 검증
            ),
            String.class
        );
        
        // ✅ 3. code_verifier 삭제
        redisTemplate.delete(CODE_VERIFIER_PREFIX + sessionId);
        
        // 토큰 추출
        return extractAccessToken(tokenResponse);
    }
}

// PKCE Challenge DTO
class PKCEChallenge {
    public String codeChallenge;
    public String method;  // "S256" 또는 "plain"
    
    public PKCEChallenge(String codeChallenge, String method) {
        this.codeChallenge = codeChallenge;
        this.method = method;
    }
}

// Spring Security에서 PKCE 자동 지원
@Configuration
public class PKCEOAuth2SecurityConfig {
    
    @Bean
    public ClientRegistration googleClientRegistration() {
        return ClientRegistration.withRegistrationId("google")
            .clientId(clientId)
            .clientSecret(clientSecret)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri(redirectUri)
            .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
            .tokenUri("https://www.googleapis.com/oauth2/v4/token")
            // ✅ PKCE 자동 사용 (Spring Security 5.2+)
            .build();
    }
}
```

### 3. redirect_uri 검증

```java
// ✅ 안전한 코드: redirect_uri 엄격한 검증
@Component
public class RedirectUriValidator {
    
    // 사전에 정의된 redirect_uri 화이트리스트
    private static final Set<String> ALLOWED_REDIRECT_URIS = Set.of(
        "https://app.example.com/login/oauth2/callback/google",
        "https://app.example.com/login/oauth2/callback/github",
        "https://app.example.com/login/oauth2/callback/facebook"
    );
    
    // redirect_uri 검증
    public boolean isValidRedirectUri(String redirectUri) {
        // ✅ 1. 정확한 일치 검사 (startsWith 금지)
        return ALLOWED_REDIRECT_URIS.contains(redirectUri);
    }
    
    // URI 파싱하여 엄격하게 검증
    public boolean validateRedirectUriStrict(String redirectUri) {
        try {
            // ✅ 2. URI 파싱
            URL url = new URL(redirectUri);
            
            // ✅ 3. 프로토콜 검증 (HTTPS 필수)
            if (!"https".equals(url.getProtocol())) {
                return false;  // HTTP는 거절
            }
            
            // ✅ 4. 호스트명 검증 (localhost/IP 제외)
            String host = url.getHost();
            if (host.equals("localhost") || host.equals("127.0.0.1") 
                || host.matches(".*\\.attacker\\..*")) {
                return false;
            }
            
            // ✅ 5. 포트 검증 (기본 포트만 허용)
            int port = url.getPort();
            if (port != -1 && port != 443 && port != 80) {
                return false;
            }
            
            // ✅ 6. 경로 검증 (정확한 경로만 허용)
            String path = url.getPath();
            String expectedPath = "/login/oauth2/callback/google";
            if (!path.equals(expectedPath)) {
                return false;
            }
            
            // ✅ 7. 쿼리 파라미터 검증 (있으면 거절)
            if (url.getQuery() != null && !url.getQuery().isEmpty()) {
                return false;
            }
            
            // ✅ 모든 검증 통과
            return ALLOWED_REDIRECT_URIS.contains(redirectUri);
        } catch (MalformedURLException e) {
            return false;
        }
    }
}

// OAuth2 요청에서 redirect_uri 검증
@Configuration
public class OAuth2ValidationConfig {
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .oauth2Login(oauth2 -> oauth2
                .authorizationEndpoint(authEndpoint -> authEndpoint
                    // ✅ 커스텀 Authorization Request Resolver로 redirect_uri 검증
                    .authorizationRequestResolver(
                        new ValidatingAuthorizationRequestResolver(
                            clientRegistrationRepository,
                            redirectUriValidator()
                        )
                    )
                )
            )
            .build();
        
        return http.build();
    }
    
    @Bean
    public RedirectUriValidator redirectUriValidator() {
        return new RedirectUriValidator();
    }
}

// 커스텀 Authorization Request Resolver
public class ValidatingAuthorizationRequestResolver 
        implements OAuth2AuthorizationRequestResolver {
    
    private final OAuth2AuthorizationRequestResolver delegate;
    private final RedirectUriValidator redirectUriValidator;
    
    public ValidatingAuthorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository,
            RedirectUriValidator redirectUriValidator) {
        this.delegate = new DefaultOAuth2AuthorizationRequestResolver(
            clientRegistrationRepository,
            "/oauth2/authorization"
        );
        this.redirectUriValidator = redirectUriValidator;
    }
    
    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        OAuth2AuthorizationRequest authRequest = delegate.resolve(request);
        
        if (authRequest != null) {
            String redirectUri = authRequest.getRedirectUri();
            
            // ✅ redirect_uri 검증
            if (!redirectUriValidator.isValidRedirectUri(redirectUri)) {
                throw new SecurityException("유효하지 않은 redirect_uri: " + redirectUri);
            }
        }
        
        return authRequest;
    }
    
    @Override
    public OAuth2AuthorizationRequest resolve(
            HttpServletRequest request,
            String clientRegistrationId) {
        return resolve(request);
    }
}
```

## 🔬 공격 원리 분석 (공격자 관점의 내부 동작)

### state 파라미터 없을 때의 CSRF 공격

```
Step 1: 공격자가 자신의 계정으로 로그인
├─ 공격자가 "Sign Up with Google" 클릭
├─ Google에서 Authorization Code 획득: code=attacker_abc123
└─ 애플리케이션에 등록되어 피해자 계정으로 가장

Step 2: 공격자가 CSRF 공격 준비
├─ 피해자에게 다음 링크 전송
├─ https://app.com/login/oauth2/callback/google?code=attacker_abc123
└─ 또는 이메일, SNS로 유포

Step 3: 피해자가 링크 클릭
├─ 애플리케이션이 code=attacker_abc123으로 토큰 교환
├─ Google에 조회: "attacker_abc123의 소유자는 누구?"
└─ Google 응답: "소유자는 attacker@gmail.com"

Step 4: 애플리케이션이 계정 생성 또는 연결
├─ 새로운 계정 생성 (attacker@gmail.com으로)
├─ 또는 기존 계정에 Google 연결
└─ 결과: 피해자 계정 = 공격자 Google 계정

Step 5: 공격자가 피해자 계정 제어
├─ 공격자가 "Sign Up with Google" 클릭
├─ attacker@gmail.com으로 로그인
└─ 피해자 계정으로 접속 (피해자는 모름!)
```

### PKCE 없을 때의 Authorization Code 탈취

```
모바일 앱 시나리오:
┌─────────────────────────────────────┐
│ 정상 플로우 (PKCE 없음)              │
├─────────────────────────────────────┤
│ 1. 정상 앱이 Google로 리다이렉트     │
│    scheme://redirect_uri?code=XYZ    │
│                                      │
│ 2. 정상 앱이 Authorization Code 받음  │
│    intent.getData()로 code=XYZ 추출   │
│                                      │
│ 3. 공격 앱이 같은 redirect_uri 등록   │
│    (또는 URI 매칭 규칙 악용)          │
│                                      │
│ 4. 공격 앱이 Authorization Code 탈취  │
│    intent.getData() → code=XYZ       │
│                                      │
│ 5. ❌ PKCE 없으면 공격 앱도 토큰 가능 │
│    POST /token                       │
│    code=XYZ                          │
│    client_id=attacker_app_id         │
│    → accessToken 획득!               │
└─────────────────────────────────────┘

✅ PKCE로 보호되는 경우:
┌─────────────────────────────────────┐
│ 1. code_verifier를 정상 앱만 알고 있음 │
│                                      │
│ 2. 공격 앱이 Authorization Code 탈취   │
│    하지만 code_verifier가 없음        │
│                                      │
│ 3. 토큰 교환 시 code_verifier 필수     │
│    POST /token                       │
│    code=XYZ                          │
│    code_verifier=onlyNormalAppKnows  │
│    client_id=attacker_app_id         │
│    → ❌ 검증 실패!                   │
│                                      │
│ 4. 공격 불가능                       │
└─────────────────────────────────────┘
```

## 💻 실전 실험 (취약점 재현 → 공격 → 방어 검증)

### 실험 1: state 파라미터 검증

```java
@SpringBootTest
public class OAuth2StateValidationTest {
    
    @Autowired
    private MockMvc mockMvc;
    
    @Autowired
    private RedisTemplate<String, String> redisTemplate;
    
    @Test
    public void testStateCsrfAttack() throws Exception {
        // ❌ 공격: 공격자의 code로 콜백
        MvcResult result = mockMvc.perform(
            get("/login/oauth2/callback/google")
                .param("code", "attacker_code_abc123")
                .param("state", "invalid_state")
        )
            .andExpect(status().isUnauthorized())  // ✅ 거절됨
            .andReturn();
    }
    
    @Test
    public void testStateValidation() throws Exception {
        // 1. Authorization 요청 (state 생성)
        MvcResult authResult = mockMvc.perform(
            get("/oauth2/authorization/google")
        )
            .andExpect(status().isFound())
            .andReturn();
        
        String location = authResult.getResponse().getRedirectedUrl();
        // state 파라미터 추출
        String state = extractStateFromUrl(location);
        
        // 2. ✅ 정상 code + 정상 state로 콜백
        MvcResult callbackResult = mockMvc.perform(
            get("/login/oauth2/callback/google")
                .param("code", "valid_code_xyz")
                .param("state", state)
        )
            .andExpect(status().isFound())  // 성공
            .andReturn();
    }
}
```

### 실험 2: PKCE 검증

```java
@SpringBootTest
public class PKCEValidationTest {
    
    @Autowired
    private PKCEOAuth2Service pkceService;
    
    @Test
    public void testPKCECodeVerifier() {
        // 1. code_verifier 생성
        PKCEChallenge challenge = pkceService.generatePKCEChallenge(
            createMockSession()
        );
        
        // 2. code_challenge 확인
        assertTrue(challenge.codeChallenge.length() > 40);
        assertEquals("S256", challenge.method);
        
        // 3. 토큰 교환 (code_verifier 필수)
        String accessToken = pkceService.exchangeCodeForTokenWithPKCE(
            createMockSession(),
            "valid_code"
        );
        
        assertNotNull(accessToken);
    }
    
    @Test
    public void testPKCEWithoutCodeVerifier() {
        // ❌ code_verifier 없이 토큰 교환 시도
        assertThrows(
            SecurityException.class,
            () -> pkceService.exchangeCodeForTokenWithPKCE(
                createDifferentSession(),  // 다른 세션
                "valid_code"
            )
        );
    }
}
```

### 실험 3: redirect_uri 검증

```java
@SpringBootTest
public class RedirectUriValidationTest {
    
    @Autowired
    private RedirectUriValidator redirectUriValidator;
    
    @Test
    public void testValidRedirectUri() {
        String validUri = "https://app.example.com/login/oauth2/callback/google";
        assertTrue(redirectUriValidator.isValidRedirectUri(validUri));
    }
    
    @Test
    public void testInvalidRedirectUri_AttackerDomain() {
        String invalidUri = "https://attacker.com/login/oauth2/callback/google";
        assertFalse(redirectUriValidator.isValidRedirectUri(invalidUri));
    }
    
    @Test
    public void testInvalidRedirectUri_SubdomainInjection() {
        String invalidUri = "https://app.example.com.attacker.com/login/oauth2/callback/google";
        assertFalse(redirectUriValidator.isValidRedirectUri(invalidUri));
    }
    
    @Test
    public void testInvalidRedirectUri_AtSymbol() {
        String invalidUri = "https://app.example.com@attacker.com/login/oauth2/callback/google";
        assertFalse(redirectUriValidator.isValidRedirectUri(invalidUri));
    }
    
    @Test
    public void testInvalidRedirectUri_HTTP() {
        String invalidUri = "http://app.example.com/login/oauth2/callback/google";
        assertFalse(redirectUriValidator.isValidRedirectUri(invalidUri));
    }
}
```

## 📊 공격 성공 조건 vs 방어 성공 조건 비교

| 항목 | 공격 성공 조건 | 방어 성공 조건 |
|------|--------------|--------------|
| **state 파라미터** | 없음 또는 검증 안함 | UUID 기반 + Redis 검증 |
| **code 일회용** | 여러 번 사용 가능 | 1회 사용 후 무효화 |
| **PKCE** | 없음 (Public Client) | code_verifier + code_challenge |
| **redirect_uri** | 와일드카드 또는 동적 | 정확한 화이트리스트 |
| **HTTPS 강제** | HTTP 허용 | HTTPS only |
| **코드 타임아웃** | 무한정 유효 | 10분 이내 |

## ⚖️ 트레이드오프 (보안 강화 vs 사용성/성능)

### 1. PKCE vs 구현 복잡도
- **보안**: PKCE 필수 (Public Client 보호)
- **복잡도**: 추가 암호화, 저장소 필요
- **트레이드오프**: 최신 라이브러리(Spring Security 5.2+)에서는 자동 지원

### 2. redirect_uri 화이트리스트 vs 유연성
- **보안**: 정확한 URI만 허용
- **유연성**: 새로운 서브도메인 추가 시 설정 변경 필요
- **트레이드오프**: 정적 화이트리스트로 충분한 경우 대부분

### 3. state 저장소 vs 무상태성
- **보안**: Redis/Session에 state 저장 (CSRF 방지)
- **무상태성**: 저장소 필요 없음
- **트레이드오프**: 대부분의 모던 앱에서 Redis/Session 사용 → 문제없음

## 📌 핵심 정리

1. **state 파라미터 필수**
   ```java
   String state = UUID.randomUUID().toString();
   redisTemplate.set(state, sessionId, 600, TimeUnit.SECONDS);
   ```

2. **PKCE 필수 (Public Client)**
   ```java
   code_verifier = generateSecureRandom(128);
   code_challenge = SHA256(code_verifier);
   ```

3. **redirect_uri 화이트리스트**
   ```java
   ALLOWED_URIS = {"https://app.example.com/callback/google"};
   if (!ALLOWED_URIS.contains(providedUri)) throw Exception;
   ```

4. **HTTPS 강제**
   ```java
   if (!"https".equals(url.getProtocol())) throw Exception;
   ```

5. **Authorization Code 일회용**
   ```java
   if (redisTemplate.hasKey("code:" + code)) {
       throw new Exception("Code already used");
   }
   redisTemplate.set("code:" + code, "used", 600, TimeUnit.SECONDS);
   ```

## 🤔 생각해볼 문제 (+ 해설)

### 문제 1: state 파라미터가 정말 필요한가? PKCE만으로는 부족한가?
**해설:**
- PKCE는 Authorization Code 탈취를 방지
- state는 Authorization Code 자체를 조작하는 공격(CSRF)를 방지
- 두 가지는 서로 다른 공격을 막음:
  - PKCE: 공격자가 탈취한 code를 사용 불가 (code_verifier 필요)
  - state: 공격자가 다른 code를 피해자에게 주입 불가 (state 검증)
- **따라서 둘 다 필수**

### 문제 2: redirect_uri를 동적으로 설정할 수 없는가?
**해설:**
- 가능하지만 매우 위험
- 예: `https://oauth-provider.com/authorize?redirect_uri=https://user_input.com`
- 공격자가 임의의 URI를 지정 가능
- **해결책**: 
  1. 정적 화이트리스트만 사용
  2. 또는 매우 엄격한 검증 (URI 파싱, 호스트명 검증 등)

### 문제 3: Authorization Code의 유효 시간이 짧으면(10초) PKCE가 필요없는가?
**해설:**
- 아니다. 네트워크 지연이나 로그 조회로 10초가 충분하지 않을 수 있음
- 또한 Authorization Code는 한 번에 전달되므로 탈취 가능성 항상 존재
- **따라서 PKCE는 별도의 추가 보호층** (code_verifier 필수)

---

<div align="center">

**[⬅️ 이전: CSRF 공격](./04-csrf-attack.md)** | **[홈으로 🏠](../README.md)** | **[다음: 브루트포스와 계정 보호 ➡️](./06-bruteforce-account-protection.md)**

</div>
