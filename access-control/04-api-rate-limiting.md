# 04. API Rate Limiting 설계 — 엔드포인트별 차등적 제한 전략

---

## 🎯 핵심 질문

모든 API 엔드포인트에 동일한 속도 제한을 적용하면 안 될까요?

예를 들어:
- 로그인 API: 분당 최대 5회
- 리소스 조회 API: 분당 최대 100회
- 결제 처리 API: 분당 최대 10회

**각 엔드포인트의 특성에 따라 다른 한도를 설정**해야 합니다. 로그인은 자주 하지 않으므로 낮은 한도로 **무차별 대입 공격(Brute Force)**을 방어하고, 조회 API는 높은 한도로 **정상 사용성**을 보장해야 합니다.

이것이 **차등적 Rate Limiting** 전략입니다.

---

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

### 실제 사고 사례 1: Rate Limiting 없는 로그인 API — 무차별 대입 공격
2021년 국내 은행 모바일 앱에서 `/api/auth/login` 엔드포인트에 Rate Limiting이 없어서:

```bash
# 공격자의 자동화된 공격
while true:
    try_login(username="customer_account", password=random_password)
    
# 1초에 100회 로그인 시도 가능
# → 하루에 약 800만 회 시도 (8,640,000 회)
# → 약 2시간 만에 약하면 비밀번호 파단 가능
```

결과: **2,000명의 고객 계정이 침입당했습니다**.

### 실제 사고 사례 2: 비용이 드는 API에 Rate Limiting 부재
클라우드 기반 이미지 변환 서비스에서 `/api/transform-image` 엔드포인트에 제한이 없었습니다:

```
정상 사용: 분당 10회 이미지 처리
공격자: 자동 스크립트로 분당 10,000회 요청

→ 월간 클라우드 비용: $500 → $50,000 (100배 증가!)
```

### 실제 사고 사례 3: 코드 검증 API에 Rate Limiting 부재
OTP 검증 API가 제한이 없어서:

```bash
# 공격자: 자동으로 모든 6자리 숫자 조합 시도
# 000000 ~ 999999 = 100만 개
# 1초에 100회 시도 → 약 3시간 내에 전수 조사 가능

GET /api/otp/verify?code=000000
GET /api/otp/verify?code=000001
...
GET /api/otp/verify?code=999999
```

### 왜 위험한가?
- **무차별 대입 공격(Brute Force)**: 비밀번호 추측 가능
- **계정 탈취**: 약한 비밀번호 대량 시도
- **서비스 거부(DoS)**: 정상 사용자 요청 처리 불가
- **경제적 손실**: 클라우드 리소스 과다 사용
- **OTP/2FA 우회**: 인증 코드 전수 조사

---

## 😱 취약한 코드 (Before — 원리를 모를 때의 구현)

### 취약점 1: Rate Limiting이 없는 기본 구현

```java
// 취약한 인증 컨트롤러
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    
    @Autowired
    private UserService userService;
    
    @Autowired
    private JwtTokenProvider tokenProvider;
    
    // 문제: 제한이 없음. 무차별 대입 공격에 취약!
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        
        User user = userService.findByUsername(request.getUsername());
        
        // 비밀번호 검증 (약 100ms 소요)
        if (!user.getPassword().equals(BCrypt.hashpw(request.getPassword(), ...))) {
            throw new UnauthorizedException("Invalid credentials");
        }
        
        String token = tokenProvider.generateToken(user);
        
        return ResponseEntity.ok(new LoginResponse(token));
    }
    
    // 문제: 비밀번호 재설정 API도 제한 없음
    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@RequestBody ForgotPasswordRequest request) {
        User user = userService.findByEmail(request.getEmail());
        
        // 임시 비밀번호 발급
        String tempPassword = generateTempPassword();
        userService.setTempPassword(user, tempPassword);
        
        // 이메일 발송 (느림: 1~2초)
        emailService.sendResetEmail(user.getEmail(), tempPassword);
        
        return ResponseEntity.ok("Check your email");
    }
}

// 취약한 조회 API
@RestController
@RequestMapping("/api/search")
public class SearchController {
    
    @Autowired
    private SearchService searchService;
    
    // 문제: 검색 API도 제한이 없음
    // → 데이터베이스 과부하 가능
    // → 복잡한 쿼리 반복 시 서버 자원 소진
    @GetMapping
    public ResponseEntity<List<SearchResult>> search(@RequestParam String query) {
        List<SearchResult> results = searchService.search(query);
        return ResponseEntity.ok(results);
    }
}

// 공격 예시
```bash
# 1. 무차별 대입 공격
for i in {1..1000000}; do
    curl -X POST http://localhost:8080/api/auth/login \
         -H "Content-Type: application/json" \
         -d "{\"username\":\"victim\",\"password\":\"password$i\"}" &
done

# 2. 복잡한 검색으로 서버 과부하
for i in {1..10000}; do
    curl "http://localhost:8080/api/search?query=*" &
done
```
```

### 취약점 2: 동일한 Rate Limiting을 모든 API에 적용

```java
// 취약한 전역 Rate Limiting (모든 API에 동일)
@Configuration
public class RateLimitingConfig {
    
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addInterceptors(InterceptorRegistry registry) {
                // 문제: 모든 API에 동일한 제한 (분당 100회)
                registry.addInterceptor(new RateLimitInterceptor(100))
                    .addPathPatterns("/**");
            }
        };
    }
}

// 문제점:
// - 로그인 API도 분당 100회 가능 (너무 높음!)
// - 조회 API는 분당 100회로 부족 (너무 낮음!)
```

### 취약점 3: 사용자 기반이 아닌 IP 기반 제한만 있는 경우

```java
// IP 기반 Rate Limiting
public class IpBasedRateLimiter {
    
    private Map<String, RateLimit> limiterByIp = new ConcurrentHashMap<>();
    
    public boolean isAllowed(String clientIp) {
        RateLimit limit = limiterByIp.getOrDefault(clientIp, new RateLimit());
        
        if (limit.requests >= 100) {
            return false;  // 제한 초과
        }
        
        limit.requests++;
        limiterByIp.put(clientIp, limit);
        return true;
    }
}

// 문제점:
// - 같은 네트워크의 여러 사용자가 한 IP 공유 가능 (프록시, NAT)
// - 한 악의적 사용자의 공격으로 다른 사용자도 피해
// - VPN 사용자는 쉽게 우회
```

---

## ✨ 방어 코드 (After — 공격 원리를 알고 설계한 구현)

### 방어 전략 1: Redis를 이용한 슬라이딩 윈도우(Sliding Window) Rate Limiter

```java
// Rate Limiting 설정 클래스
public class RateLimitConfig {
    
    // 엔드포인트별 한도 설정
    public static final Map<String, RateLimitRule> RATE_LIMIT_RULES = Map.of(
        // 보안 관련 (엄격함)
        "POST:/api/auth/login", new RateLimitRule(5, 60),  // 분당 5회
        "POST:/api/auth/register", new RateLimitRule(3, 60),  // 분당 3회
        "POST:/api/auth/otp/verify", new RateLimitRule(10, 60),  // 분당 10회
        
        // 작성 관련 (중간)
        "POST:/api/posts", new RateLimitRule(30, 60),  // 분당 30회
        "PUT:/api/posts/**", new RateLimitRule(30, 60),
        
        // 조회 관련 (관대함)
        "GET:/api/posts", new RateLimitRule(1000, 60),  // 분당 1000회
        "GET:/api/search", new RateLimitRule(500, 60),
        
        // 결제 (매우 엄격함)
        "POST:/api/payments", new RateLimitRule(5, 60),  // 분당 5회
        
        // 기본값
        "DEFAULT", new RateLimitRule(100, 60)
    );
}

// Rate Limit Rule
@Data
@NoArgsConstructor
@AllArgsConstructor
public class RateLimitRule {
    private int maxRequests;      // 최대 요청 수
    private int windowSeconds;    // 시간 윈도우 (초)
}

// Redis 기반 Rate Limiter
@Component
public class RedisRateLimiter {
    
    @Autowired
    private RedisTemplate<String, Long> redisTemplate;
    
    @Autowired
    private RateLimitConfig rateLimitConfig;
    
    // 키 생성: userId + endpointMethod + endpointPath
    private String generateKey(Long userId, String method, String path) {
        return String.format("rate-limit:%d:%s:%s", userId, method, path);
    }
    
    // IP 기반 키 (사용자 미인증 시)
    private String generateIpKey(String clientIp, String method, String path) {
        return String.format("rate-limit-ip:%s:%s:%s", clientIp, method, path);
    }
    
    // 요청이 허용되는지 확인
    public boolean isAllowed(String userId, String method, String path, String clientIp) {
        String key;
        RateLimitRule rule = getRateLimitRule(method, path);
        
        if (userId != null) {
            key = generateKey(Long.parseLong(userId), method, path);
        } else {
            key = generateIpKey(clientIp, method, path);
        }
        
        Long currentCount = redisTemplate.opsForValue().get(key);
        
        if (currentCount == null) {
            // 첫 요청
            redisTemplate.opsForValue().set(key, 1L, 
                Duration.ofSeconds(rule.getWindowSeconds()));
            return true;
        }
        
        if (currentCount >= rule.getMaxRequests()) {
            return false;  // 제한 초과
        }
        
        // 요청 카운트 증가
        redisTemplate.opsForValue().increment(key);
        return true;
    }
    
    // 남은 시간 조회
    public Long getTimeToResetSeconds(String userId, String method, String path) {
        String key = generateKey(Long.parseLong(userId), method, path);
        return redisTemplate.getExpire(key, TimeUnit.SECONDS);
    }
    
    // 남은 할당량 조회
    public Long getRemainingRequests(String userId, String method, String path) {
        String key = generateKey(Long.parseLong(userId), method, path);
        Long currentCount = redisTemplate.opsForValue().get(key);
        RateLimitRule rule = getRateLimitRule(method, path);
        
        if (currentCount == null) {
            return (long) rule.getMaxRequests();
        }
        
        return Math.max(0, rule.getMaxRequests() - currentCount);
    }
    
    private RateLimitRule getRateLimitRule(String method, String path) {
        String ruleKey = method + ":" + path;
        return RateLimitConfig.RATE_LIMIT_RULES.getOrDefault(
            ruleKey,
            RateLimitConfig.RATE_LIMIT_RULES.get("DEFAULT")
        );
    }
}

// Spring Interceptor로 Rate Limiting 적용
@Component
public class RateLimitingInterceptor implements HandlerInterceptor {
    
    @Autowired
    private RedisRateLimiter rateLimiter;
    
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, 
                            Object handler) throws Exception {
        
        String method = request.getMethod();
        String path = request.getRequestURI();
        String clientIp = getClientIp(request);
        
        // SecurityContext에서 사용자 ID 추출 (인증된 경우)
        String userId = null;
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated()) {
            userId = auth.getPrincipal().toString();
        }
        
        // Rate Limiting 확인
        if (!rateLimiter.isAllowed(userId, method, path, clientIp)) {
            
            // 429 Too Many Requests 응답
            response.setStatus(HttpServletResponse.SC_TOO_MANY_REQUESTS);
            response.setContentType("application/json");
            
            // Retry-After 헤더 설정
            Long resetTime = rateLimiter.getTimeToResetSeconds(userId, method, path);
            response.setHeader("Retry-After", resetTime.toString());
            
            // 응답 본문
            String body = String.format("""
                {
                  "error": "Too Many Requests",
                  "message": "Rate limit exceeded",
                  "retryAfterSeconds": %d,
                  "resetTime": "%s"
                }
                """, resetTime, Instant.now().plusSeconds(resetTime).toString());
            
            response.getWriter().write(body);
            return false;
        }
        
        // Rate Limit 정보를 응답 헤더에 추가
        Long remaining = rateLimiter.getRemainingRequests(userId, method, path);
        response.setHeader("X-RateLimit-Remaining", remaining.toString());
        response.setHeader("X-RateLimit-Reset", 
                          String.valueOf(System.currentTimeMillis() + 
                                        rateLimiter.getTimeToResetSeconds(userId, method, path) * 1000));
        
        return true;
    }
    
    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("X-Real-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        return ip.split(",")[0];  // 여러 IP인 경우 첫 번째만
    }
}

// Configuration: Interceptor 등록
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {
    
    @Autowired
    private RateLimitingInterceptor rateLimitingInterceptor;
    
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(rateLimitingInterceptor)
            .addPathPatterns("/**");
    }
}
```

### 방어 전략 2: Bucket4j 라이브러리를 이용한 구현

```xml
<!-- Maven 의존성 -->
<dependency>
    <groupId>com.github.vladimir-bukhtoyarov</groupId>
    <artifactId>bucket4j-core</artifactId>
    <version>7.6.0</version>
</dependency>
```

```java
// Bucket4j를 이용한 Rate Limiter
@Component
public class Bucket4jRateLimiter {
    
    private Map<String, Bucket> bucketsByUserId = new ConcurrentHashMap<>();
    
    public Bucket resolveBucket(String userId, String endpoint) {
        return bucketsByUserId.computeIfAbsent(userId + ":" + endpoint, 
            k -> createBucket(endpoint));
    }
    
    private Bucket createBucket(String endpoint) {
        RateLimitRule rule = getRateLimitRule(endpoint);
        
        // 토큰 소비 방식: maxRequests 토큰, windowSeconds 간 재충전
        Bandwidth limit = Bandwidth.classic(
            rule.getMaxRequests(), 
            Refill.intervally(rule.getMaxRequests(), 
                            Duration.ofSeconds(rule.getWindowSeconds()))
        );
        
        return Bucket4j.builder()
            .addLimit(limit)
            .build();
    }
    
    public boolean consumeToken(String userId, String endpoint) {
        Bucket bucket = resolveBucket(userId, endpoint);
        return bucket.tryConsume(1);
    }
    
    private RateLimitRule getRateLimitRule(String endpoint) {
        // endpoint에 따른 규칙 반환
        return new RateLimitRule(100, 60);  // 기본값
    }
}

// Bucket4j를 이용한 컨트롤러
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    
    @Autowired
    private Bucket4jRateLimiter bucket4jRateLimiter;
    
    @Autowired
    private UserService userService;
    
    @PostMapping("/login")
    public ResponseEntity<?> login(
            @RequestBody LoginRequest request,
            @AuthenticationPrincipal CustomUserDetails userDetails) {
        
        String userId = userDetails != null ? userDetails.getUserId().toString() : "anonymous";
        
        // Rate Limiting 확인
        if (!bucket4jRateLimiter.consumeToken(userId, "/api/auth/login")) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header("Retry-After", "60")
                .body(new ErrorResponse("Too many login attempts"));
        }
        
        // 로그인 처리
        User user = userService.authenticate(request.getUsername(), request.getPassword());
        
        return ResponseEntity.ok(new LoginResponse(user.getToken()));
    }
}
```

### 방어 전략 3: 메서드 레벨 Rate Limiting (어노테이션)

```java
// 커스텀 Rate Limit 어노테이션
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RateLimit {
    int maxRequests() default 100;
    int windowSeconds() default 60;
    String keyPrefix() default "";  // userId / clientIp / combination
}

// AOP를 이용한 Rate Limit 적용
@Aspect
@Component
public class RateLimitAspect {
    
    @Autowired
    private RedisRateLimiter rateLimiter;
    
    @Around("@annotation(rateLimit)")
    public Object rateLimitCheck(ProceedingJoinPoint joinPoint, RateLimit rateLimit) 
            throws Throwable {
        
        HttpServletRequest request = getRequest();
        String clientIp = getClientIp(request);
        String method = request.getMethod();
        String path = request.getRequestURI();
        
        // 사용자 ID 추출
        String userId = null;
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated()) {
            userId = auth.getPrincipal().toString();
        }
        
        // Rate Limiting 확인
        if (!rateLimiter.isAllowed(userId, method, path, clientIp)) {
            throw new RateLimitExceededException("Rate limit exceeded");
        }
        
        return joinPoint.proceed();
    }
}

// 사용 예
@RestController
public class UserController {
    
    @RateLimit(maxRequests = 5, windowSeconds = 60)
    @PostMapping("/api/auth/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        // ...
    }
    
    @RateLimit(maxRequests = 1000, windowSeconds = 60)
    @GetMapping("/api/posts")
    public ResponseEntity<List<PostDto>> getPosts() {
        // ...
    }
}
```

### 방어 전략 4: 사용자 신뢰도 기반 동적 Rate Limiting

```java
// 사용자 신뢰도에 따른 동적 Rate Limiting
@Component
public class DynamicRateLimiter {
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private RedisRateLimiter redisRateLimiter;
    
    public RateLimitRule getDynamicRule(Long userId, String endpoint) {
        User user = userRepository.findById(userId).orElse(null);
        
        if (user == null) {
            // 미인증 사용자: 가장 엄격한 제한
            return new RateLimitRule(10, 60);
        }
        
        if (user.isEmailVerified() && user.isPhoneVerified()) {
            // 완전히 검증된 사용자: 관대한 제한
            return new RateLimitRule(500, 60);
        }
        
        if (user.isEmailVerified()) {
            // 부분 검증: 중간 제한
            return new RateLimitRule(100, 60);
        }
        
        // 기본: 엄격한 제한
        return new RateLimitRule(30, 60);
    }
    
    public boolean isAllowedDynamic(Long userId, String endpoint, String clientIp) {
        RateLimitRule rule = getDynamicRule(userId, endpoint);
        
        String key = String.format("rate-limit:%d:%s", userId, endpoint);
        Long currentCount = getRedisCount(key);
        
        if (currentCount == null) {
            setRedisCount(key, 1, rule.getWindowSeconds());
            return true;
        }
        
        if (currentCount >= rule.getMaxRequests()) {
            return false;
        }
        
        incrementRedisCount(key);
        return true;
    }
}
```

---

## 🔬 공격 원리 분석 (공격자 관점의 내부 동작)

### 공격 시나리오 1: 무차별 대입 공격(Brute Force)

```
Step 1: 약한 비밀번호 대상 선정
┌──────────────────────────────────┐
│ 공격자가 수집한 사용자 목록:      │
│ - john@example.com               │
│ - mary@example.com               │
│ - admin                          │
│ - user123                        │
└──────────────────────────────────┘

Step 2: 일반적인 비밀번호 리스트 준비
┌──────────────────────────────────┐
│ RockYou 데이터셋에서 추출:        │
│ - password                       │
│ - 123456                         │
│ - 12345678                       │
│ - qwerty                         │
│ - abc123                         │
│ - ... (상위 100,000개)           │
└──────────────────────────────────┘

Step 3: 자동화된 공격 스크립트
┌──────────────────────────────────┐
│ 분당 1,000회 로그인 시도 가능     │
│ (Rate Limiting 없을 경우)         │
│                                  │
│ 100,000개 비밀번호 시도:         │
│ 100,000 / 1,000 = 100분 = 1.6시간│
└──────────────────────────────────┘

Step 4: 공격 성공
┌──────────────────────────────────┐
│ 약한 비밀번호의 계정 탈취         │
│ (보통 20-30% 성공률)              │
└──────────────────────────────────┘
```

### 공격 시나리오 2: OTP/코드 전수 조사

```
Step 1: OTP 조회 API 발견
┌────────────────────────────────┐
│ GET /api/otp/verify?code=123456│
│ → 200 OK 또는 400 Bad Request   │
└────────────────────────────────┘

Step 2: 속도 확인
┌────────────────────────────────┐
│ Rate Limiting이 없으면:         │
│ 분당 10,000회 이상 가능         │
└────────────────────────────────┘

Step 3: 6자리 코드 전수 조사
┌────────────────────────────────┐
│ 000000 ~ 999999 = 1,000,000개  │
│ 분당 10,000회 시도 가능 → 100분 │
│ 즉, 약 2시간 내에 모든 코드 시도│
└────────────────────────────────┘

Step 4: 성공 확률
┌────────────────────────────────┤
│ OTP 유효 시간이 10분이면:       │
│ 2시간 내에 다섯 번 기회 제공     │
│ (10분 단위로 새로운 OTP 발급)    │
│ → 높은 확률로 공격 성공         │
└────────────────────────────────┘
```

---

## 💻 실전 실험 (취약점 재현 → 공격 → 방어 검증)

### 실험 1: Redis Rate Limiter 테스트

```java
@SpringBootTest
public class RedisRateLimiterTest {
    
    @Autowired
    private RedisRateLimiter redisRateLimiter;
    
    @Autowired
    private RedisTemplate<String, Long> redisTemplate;
    
    @Before
    public void setup() {
        // Redis 초기화
        redisTemplate.getConnectionFactory().getConnection().flushAll();
    }
    
    @Test
    public void testRateLimiter_WithinLimit_ShouldAllow() {
        // 분당 5회 제한인 로그인 API
        for (int i = 0; i < 5; i++) {
            boolean allowed = redisRateLimiter.isAllowed(
                "user123", "POST", "/api/auth/login", "192.168.1.1"
            );
            assertTrue(allowed, "Request " + (i + 1) + " should be allowed");
        }
    }
    
    @Test
    public void testRateLimiter_ExceedsLimit_ShouldDeny() {
        // 6번째 요청은 거부
        for (int i = 0; i < 5; i++) {
            redisRateLimiter.isAllowed(
                "user123", "POST", "/api/auth/login", "192.168.1.1"
            );
        }
        
        // 6번째 요청
        boolean allowed = redisRateLimiter.isAllowed(
            "user123", "POST", "/api/auth/login", "192.168.1.1"
        );
        
        assertFalse(allowed, "6th request should be denied");
    }
    
    @Test
    public void testRateLimiter_DifferentEndpoints_SeparateLimits() {
        // 로그인 API: 분당 5회
        for (int i = 0; i < 5; i++) {
            redisRateLimiter.isAllowed(
                "user123", "POST", "/api/auth/login", "192.168.1.1"
            );
        }
        
        // 게시물 조회 API: 분당 1000회 (다른 제한)
        boolean allowed = redisRateLimiter.isAllowed(
            "user123", "GET", "/api/posts", "192.168.1.1"
        );
        
        // 게시물 API는 제한에 도달하지 않음
        assertTrue(allowed, "Different endpoint should have separate limit");
    }
    
    @Test
    public void testRateLimiter_TimeWindowReset() throws InterruptedException {
        // 5회 요청
        for (int i = 0; i < 5; i++) {
            redisRateLimiter.isAllowed(
                "user123", "POST", "/api/auth/login", "192.168.1.1"
            );
        }
        
        // 6번째는 거부
        assertFalse(redisRateLimiter.isAllowed(
            "user123", "POST", "/api/auth/login", "192.168.1.1"
        ));
        
        // 시간 윈도우 초 이상 대기 (실제로는 1초 정도)
        // → 실제 테스트에서는 시뮬레이션
        
        // 시간 윈도우 후: 다시 요청 가능
        // (테스트에서는 Redis 키를 직접 삭제하여 시뮬레이션)
        String key = "rate-limit:123:POST:/api/auth/login";
        redisTemplate.delete(key);
        
        assertTrue(redisRateLimiter.isAllowed(
            "user123", "POST", "/api/auth/login", "192.168.1.1"
        ), "After time window, request should be allowed");
    }
}
```

### 실험 2: 실제 HTTP 요청 테스트

```bash
#!/bin/bash

# 테스트 1: 로그인 API Rate Limiting 확인
echo "=== Login API Rate Limiting Test ==="

for i in {1..10}; do
    response=$(curl -s -w "\n%{http_code}" -X POST http://localhost:8080/api/auth/login \
        -H "Content-Type: application/json" \
        -d '{"username":"testuser","password":"wrongpassword"}')
    
    http_code=$(echo "$response" | tail -n 1)
    body=$(echo "$response" | head -n -1)
    
    echo "Request $i: HTTP $http_code"
    
    if [ "$http_code" = "429" ]; then
        echo "Rate limit exceeded at request $i"
        echo "Retry-After header:"
        curl -s -i -X POST http://localhost:8080/api/auth/login \
            -H "Content-Type: application/json" \
            -d '{"username":"testuser","password":"wrongpassword"}' | grep "Retry-After"
        break
    fi
done

# 테스트 2: 조회 API는 높은 한도 확인
echo -e "\n=== Search API Rate Limiting Test ==="

for i in {1..100}; do
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        http://localhost:8080/api/search?query=test)
    
    if [ "$http_code" = "429" ]; then
        echo "Rate limit exceeded at request $i"
        break
    fi
    
    if [ $((i % 20)) -eq 0 ]; then
        echo "Request $i: HTTP $http_code (OK)"
    fi
done

echo "Completed: Search API can handle 100+ requests"

# 테스트 3: 다른 사용자는 독립적인 제한
echo -e "\n=== User-based Rate Limiting Test ==="

echo "User 1 - 5 requests:"
for i in {1..5}; do
    curl -s -X POST http://localhost:8080/api/auth/login \
        -H "Authorization: Bearer user1_token" \
        -H "Content-Type: application/json" \
        -d '{"username":"testuser","password":"wrongpassword"}' > /dev/null
done

echo "User 1 - 6th request (should fail):"
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
    -X POST http://localhost:8080/api/auth/login \
    -H "Authorization: Bearer user1_token" \
    -H "Content-Type: application/json" \
    -d '{"username":"testuser","password":"wrongpassword"}'

echo "User 2 - 1st request (should succeed):"
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
    -X POST http://localhost:8080/api/auth/login \
    -H "Authorization: Bearer user2_token" \
    -H "Content-Type: application/json" \
    -d '{"username":"testuser","password":"wrongpassword"}'
```

### 실험 3: 무차별 대입 공격 시뮬레이션

```java
@SpringBootTest
@AutoConfigureMockMvc
public class BruteForceAttackSimulation {
    
    @Autowired
    private MockMvc mockMvc;
    
    @Test
    public void testBruteForce_Vulnerable_NoRateLimit() throws Exception {
        // Rate Limiting이 없을 경우: 1초에 100회 시도 가능
        List<String> commonPasswords = List.of(
            "password", "123456", "qwerty", "abc123", "letmein"
        );
        
        long startTime = System.currentTimeMillis();
        int successCount = 0;
        
        for (String password : commonPasswords) {
            MvcResult result = mockMvc.perform(
                post("/api/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("{\"username\":\"admin\",\"password\":\"" + password + "\"}")
            ).andReturn();
            
            if (result.getResponse().getStatus() == 200) {
                successCount++;
            }
        }
        
        long elapsedMs = System.currentTimeMillis() - startTime;
        
        // 5개 비밀번호를 시도하는데 100ms 미만 (무제한 가능)
        assertTrue(elapsedMs < 100, "Attack too fast without rate limiting");
    }
    
    @Test
    public void testBruteForce_Defended_WithRateLimit() throws Exception {
        // Rate Limiting이 있을 경우: 분당 5회로 제한
        List<String> commonPasswords = List.of(
            "password", "123456", "qwerty", "abc123", "letmein"
        );
        
        int blockedCount = 0;
        
        for (int i = 0; i < commonPasswords.size(); i++) {
            String password = commonPasswords.get(i);
            
            MvcResult result = mockMvc.perform(
                post("/api/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("{\"username\":\"admin\",\"password\":\"" + password + "\"}")
            ).andReturn();
            
            int status = result.getResponse().getStatus();
            
            if (status == 429) {
                blockedCount++;
            }
        }
        
        // 5회째부터는 Rate Limit으로 인해 거부됨
        assertTrue(blockedCount > 0, "Rate limit should block requests");
    }
}
```

---

## 📊 공격 성공 조건 vs 방어 성공 조건 비교

| 항목 | 공격 성공 조건 | 방어 성공 조건 |
|------|--------------|--------------|
| **Rate Limiting 여부** | 없음 | 엔드포인트별 차등 설정 |
| **사용자 기반 식별** | IP 기반만 (우회 가능) | 사용자 ID 기반 |
| **제한 단위** | 전역 동일 | 사용자별, 엔드포인트별 |
| **시간 윈도우** | 고정 또는 없음 | 슬라이딩 윈도우 |
| **응답 헤더** | 없음 | Retry-After, X-RateLimit-* |
| **동작** | 모든 요청 수락 | 429 Too Many Requests |
| **공격 시간** | 몇 분 ~ 몇 시간 | 불가능 또는 수일 이상 |

---

## ⚖️ 트레이드오프 (보안 강화 vs 사용성/성능)

### 트레이드오프 1: 제한 강도 vs 사용성

```
너무 강한 제한:
- 로그인 분당 5회 → 정상 사용자가 5번 실패하면 1시간 차단
- 조회 분당 100회 → 빠른 페이지 탐색 불가

너무 약한 제한:
- 로그인 분당 1000회 → 무차별 대입 공격 우려
```

**해결책**: 사용자 신뢰도 기반 동적 제한

```java
// 검증된 이메일/휴대폰: 높은 한도
// 미검증 계정: 낮은 한도
```

### 트레이드오프 2: Redis 의존성 vs 성능

```
Redis 사용:
+ 분산 환경에서 동작
+ 정확한 카운팅
- Redis 의존성 추가
- 네트워크 지연

메모리 기반 카운팅:
+ 빠름
+ 의존성 없음
- 서버 재시작 시 초기화
- 확장성 문제
```

**해결책**: 하이브리드 방식

```java
// 로컬 메모리 캐시 + Redis 백업
@Component
public class HybridRateLimiter {
    private Map<String, LocalCounter> localCache = new ConcurrentHashMap<>();
    
    @Autowired
    private RedisTemplate<String, Long> redisTemplate;
    
    public boolean isAllowed(String userId, String endpoint) {
        // 1. 로컬 캐시에서 빠르게 확인
        LocalCounter counter = localCache.get(userId + ":" + endpoint);
        if (counter != null && counter.isValid()) {
            return counter.consume();
        }
        
        // 2. Redis에서 정확한 값 조회
        Long redisCount = redisTemplate.opsForValue().get(userId + ":" + endpoint);
        
        // 3. 로컬 캐시에 동기화
        if (redisCount != null) {
            localCache.put(userId + ":" + endpoint, new LocalCounter(redisCount));
        }
        
        return true;
    }
}
```

### 트레이드오프 3: IP 기반 vs 사용자 기반

```
IP 기반:
+ 미인증 사용자도 차단 가능
- 같은 네트워크 피해
- VPN으로 우회

사용자 기반:
+ 개별 사용자 보호
- 미인증 사용자는 IP로만 가능
```

**해결책**: 하이브리드

```java
public boolean isAllowed(String userId, String endpoint, String clientIp) {
    // 인증된 사용자는 사용자 ID로
    if (userId != null) {
        return isAllowedByUserId(userId, endpoint);
    }
    
    // 미인증은 IP로
    return isAllowedByIp(clientIp, endpoint);
}
```

---

## 📌 핵심 정리

1. **Rate Limiting의 중요성**: 무차별 대입 공격, 서비스 거부 방어
2. **차등적 제한**: 
   - 로그인: 분당 5회
   - OTP: 분당 10회
   - 조회: 분당 1000회
   - 결제: 분당 10회
3. **구현 방식**:
   - Redis 슬라이딩 윈도우
   - Bucket4j 라이브러리
   - Spring Interceptor
   - AOP 어노테이션
4. **식별 방식**:
   - 사용자 ID 기반 (인증된 경우)
   - IP 기반 (미인증)
5. **응답**:
   - HTTP 429 Too Many Requests
   - Retry-After 헤더
   - X-RateLimit-* 헤더

---

## 🤔 생각해볼 문제 (+ 해설)

### 문제 1: 같은 IP에서 여러 사용자가 접근하면?

**상황**: 회사 네트워크에서 100명이 같은 공인 IP로 접근

**해설**:
사용자 기반 제한을 사용하면 해결됩니다:

```java
// IP 기반이면 문제:
// 한 사용자의 공격으로 모든 사용자 차단

// 사용자 기반이면 해결:
// 각 사용자의 할당량 독립적 관리
```

---

### 문제 2: API 사용량이 정상인데도 차단되면?

**상황**: 매달 1일에 많은 데이터 동기화 처리

**해설**:
사용자 신뢰도 기반 제한을 사용하세요:

```java
@Data
class User {
    private boolean emailVerified;
    private boolean phoneVerified;
    private int accountAge;  // 개월 수
}

// 오래된 계정 + 검증된 계정 → 높은 한도
if (user.getAccountAge() > 12 && user.isEmailVerified()) {
    maxRequests = 10000;  // 높은 한도
}
```

---

### 문제 3: 관리자는 Rate Limiting을 무시해야 하나?

**상황**: 시스템 관리자가 벌크 작업 필요

**해설**:
특정 IP나 API 키로 예외를 둡니다:

```java
public boolean isAllowed(String userId, String endpoint, String clientIp) {
    // 관리자 IP는 예외
    if (isAdminIp(clientIp)) {
        return true;
    }
    
    // API 키가 있으면 높은 한도
    if (apiKey != null && isValidApiKey(apiKey)) {
        return checkHighLimitRateLimit(userId, endpoint);
    }
    
    return checkNormalRateLimit(userId, endpoint);
}
```

<div align="center">

**[⬅️ 이전: Mass Assignment](./03-mass-assignment.md)** | **[홈으로 🏠](../README.md)** | **[다음: JWT 권한 클레임 검증 ➡️](./05-jwt-claims-validation.md)**

</div>
