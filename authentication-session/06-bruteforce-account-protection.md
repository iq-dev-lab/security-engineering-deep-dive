# 브루트포스 공격과 계정 보호
---

## 🎯 핵심 질문
Rate Limiting이 없는 로그인 API는 공격자에게 무방비 상태다. 누군가 1초에 1,000개의 비밀번호를 시도할 수 있다면? 모든 계정을 몇 시간 안에 해킹할 수 있지 않을까?

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

### LinkedIn 브루트포스 공격 (2012)
LinkedIn의 로그인 API에 Rate Limiting이 없었다:
1. 공격자가 650만 개의 비밀번호 해시 탈취
2. 오프라인에서 Rainbow Table 사용하여 해시 크래킹
3. 크래킹된 비밀번호로 자동 로그인 시도
4. Rate Limiting이 없어서 모든 계정을 몇 시간 안에 손상

### Twitter 계정 탈취 (2020)
공격자가 Twitter 직원 계정을 통해 접근:
1. Rate Limiting 있었지만, 구성이 약했음
2. 공격자가 비밀번호 리셋 + SMS 인증서 탈취
3. 계정 탈취 후 저명인 계정에서 암호화폐 사기

### Amazon AWS 계정 탈취 (2017년대)
1. 약한 비밀번호를 가진 계정에 브루트포스
2. Rate Limiting이 IP 기반이라 프록시 사용으로 우회
3. 계정 접근 후 EC2 인스턴스를 암호화폐 채굴에 사용

### Uber의 계정 잠금 역설 (DoS 공격)
Uber는 계정 잠금으로 브루트포스를 방어했는데:
1. 공격자가 의도적으로 다른 사용자의 계정에 로그인 실패 시도
2. 그 사용자의 계정이 잠금됨 (서비스 거부)
3. 정상 사용자가 자신 계정에 접속 불가 (DoS)

## 😱 취약한 코드 (Before — 원리를 모를 때의 구현)

### 1. Rate Limiting이 없는 경우

```java
// ❌ 취약한 코드: Rate Limiting 없음
@RestController
public class VulnerableBruteForceController {
    
    @Autowired
    private UserService userService;
    
    @PostMapping("/login")
    public ResponseEntity<String> login(
            @RequestBody LoginRequest request) {
        
        // ❌ Rate Limiting 없음
        // 공격자가 초당 1,000개의 로그인 시도 가능
        
        User user = userService.findByUsername(request.getUsername());
        
        if (user != null && 
            passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            
            return ResponseEntity.ok("로그인 성공");
        } else {
            return ResponseEntity.status(401).body("자격증명 오류");
        }
    }
}

// 공격 시나리오
// 1. 공격자가 단어 목록(사전) 다운로드
//    - 일반적인 비밀번호 100만 개 (rockyou.txt 등)
//    - 또는 유출된 비밀번호 데이터베이스
//
// 2. 공격자가 자동화 스크립트 작성
//    for password in password_list:
//        POST /login
//        username=target_username
//        password=password
//
// 3. Rate Limiting이 없으므로 초당 1,000개 시도 가능
//    1,000,000개 / 1,000 per sec = 1,000초 (약 17분)
//
// 4. 결과: 17분 안에 100만 개 비밀번호 중 일치하는 것 발견
//    (또는 부분 일치 찾음)
//
// 5. 공격자가 계정 접근 → 개인정보, 금융 정보 탈취

// Python 공격 코드 예시
import requests

username = "target_user"
password_list = open("rockyou.txt").readlines()

for password in password_list:
    response = requests.post(
        "https://app.com/login",
        json={
            "username": username,
            "password": password.strip()
        }
    )
    
    if response.status_code == 200:
        print(f"[+] 비밀번호 찾음: {password}")
        break
    else:
        print(f"[-] {password} 실패")
```

### 2. 계정 잠금이 DoS 공격으로 악용되는 경우

```java
// ❌ 취약한 코드: 계정 잠금이 DoS 공격이 됨
@Service
public class VulnerableAccountLockService {
    
    private static final int MAX_LOGIN_ATTEMPTS = 5;
    
    @Autowired
    private UserRepository userRepository;
    
    public void recordFailedLogin(String username) {
        User user = userRepository.findByUsername(username).orElse(null);
        
        if (user != null) {
            user.incrementFailedLoginAttempts();
            
            // ❌ 문제: MAX_LOGIN_ATTEMPTS 도달 시 계정 잠금
            if (user.getFailedLoginAttempts() >= MAX_LOGIN_ATTEMPTS) {
                user.setAccountLocked(true);  // ← DoS 공격이 됨
                userRepository.save(user);
            }
        }
    }
}

// 공격 시나리오
// 1. 공격자가 다른 사용자의 계정을 표적
//    target_username = "john_doe"
//
// 2. 공격자가 의도적으로 로그인 실패 유도
//    POST /login
//    username=john_doe
//    password=wrong_password
//
// 3. 5번의 실패 시도 후 계정 잠금
//    (공격자가 5개의 다른 비밀번호만 시도하면 됨)
//
// 4. 정상 사용자 john_doe는 자신의 올바른 비밀번호로도 로그인 불가
//    "계정이 잠금되었습니다"
//
// 5. 결과: 정상 사용자의 서비스 접근 불가 (DoS 공격)
//
// 6. 공격자가 여러 계정에 반복하면
//    서비스 전체가 마비될 수 있음
```

### 3. Rate Limiting 우회 (IP 기반)

```java
// ❌ 취약한 코드: IP 기반 Rate Limiting (프록시로 우회 가능)
@Component
public class VulnerableIpBasedRateLimiter {
    
    @Autowired
    private RedisTemplate<String, String> redisTemplate;
    
    private static final int MAX_ATTEMPTS = 10;
    private static final long WINDOW_SECONDS = 60;
    
    public boolean isRateLimited(String clientIp) {
        String key = "login_attempts:" + clientIp;
        String attempts = redisTemplate.opsForValue().get(key);
        
        int count = attempts != null ? Integer.parseInt(attempts) : 0;
        
        if (count >= MAX_ATTEMPTS) {
            return true;  // 차단
        }
        
        // 시도 횟수 증가
        redisTemplate.opsForValue().increment(key);
        redisTemplate.expire(key, WINDOW_SECONDS, TimeUnit.SECONDS);
        
        return false;  // 허용
    }
}

// 공격 시나리오
// 1. 공격자가 IP 기반 Rate Limiting 인식
//
// 2. 공격자가 프록시/VPN 사용
//    - 매번 다른 IP로 요청
//    - 또는 Tor 네트워크 사용
//    - 또는 분산 봇넷 사용
//
// 3. Rate Limiting 우회
//    IP 1: 10번 시도 (5초)
//    IP 2: 10번 시도 (5초)
//    IP 3: 10번 시도 (5초)
//    ...
//    IP 100: 10번 시도
//
// 4. 5초 * 100 = 500초 안에 1,000개 비밀번호 시도
//    (또는 병렬로 동시 진행 → 훨씬 빠름)
//
// 5. 결과: Rate Limiting이 효과 없음
```

## ✨ 방어 코드 (After — 공격 원리를 알고 설계한 구현)

### 1. 슬라이딩 윈도우 기반 Rate Limiter

```java
// ✅ 안전한 코드: Redis 기반 슬라이딩 윈도우 Rate Limiter
@Component
public class SlidingWindowRateLimiter {
    
    @Autowired
    private RedisTemplate<String, Long> redisTemplate;
    
    private static final int MAX_ATTEMPTS_PER_MINUTE = 5;
    private static final long WINDOW_SIZE_SECONDS = 60;
    private static final String LOGIN_ATTEMPT_PREFIX = "login_attempts:";
    
    public RateLimitResult checkRateLimit(String username) {
        String key = LOGIN_ATTEMPT_PREFIX + username;
        long now = System.currentTimeMillis();
        
        // ✅ 1. 슬라이딩 윈도우 범위 계산
        long windowStart = now - (WINDOW_SIZE_SECONDS * 1000);
        
        // ✅ 2. Redis Sorted Set에서 윈도우 내의 시도 제거
        redisTemplate.opsForZSet().removeRangeByScore(
            key,
            0,
            windowStart
        );
        
        // ✅ 3. 현재 윈도우 내의 시도 횟수 조회
        long attemptCount = redisTemplate.opsForZSet().size(key);
        
        if (attemptCount >= MAX_ATTEMPTS_PER_MINUTE) {
            // Rate limit 초과
            long oldestAttemptTime = (Long) 
                redisTemplate.opsForZSet().rangeByScore(key, 0, Long.MAX_VALUE).stream()
                    .min((o1, o2) -> Long.compare((Long)o1, (Long)o2))
                    .orElse(now);
            
            long retryAfterSeconds = (oldestAttemptTime + WINDOW_SIZE_SECONDS * 1000 - now) / 1000;
            
            return new RateLimitResult(false, attemptCount, retryAfterSeconds);
        }
        
        // ✅ 4. 현재 시도 기록 (Sorted Set에 타임스탬프 저장)
        redisTemplate.opsForZSet().add(key, now, now);
        
        // ✅ 5. TTL 설정 (메모리 누수 방지)
        redisTemplate.expire(key, WINDOW_SIZE_SECONDS, TimeUnit.SECONDS);
        
        return new RateLimitResult(true, attemptCount + 1, 0);
    }
}

// Rate Limit 결과
class RateLimitResult {
    public boolean allowed;
    public long attemptCount;
    public long retryAfterSeconds;
    
    public RateLimitResult(boolean allowed, long attemptCount, long retryAfterSeconds) {
        this.allowed = allowed;
        this.attemptCount = attemptCount;
        this.retryAfterSeconds = retryAfterSeconds;
    }
}

// 필터에서 Rate Limiting 적용
@Component
public class LoginRateLimitFilter extends OncePerRequestFilter {
    
    @Autowired
    private SlidingWindowRateLimiter rateLimiter;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        
        if (request.getRequestURI().equals("/login")) {
            String username = request.getParameter("username");
            
            if (username != null) {
                // ✅ username 기반 Rate Limiting
                RateLimitResult result = rateLimiter.checkRateLimit(username);
                
                if (!result.allowed) {
                    response.setStatus(HttpServletResponse.SC_TOO_MANY_REQUESTS);
                    response.setHeader("Retry-After", String.valueOf(result.retryAfterSeconds));
                    response.getWriter().write(
                        "로그인 시도 횟수를 초과했습니다. " + 
                        result.retryAfterSeconds + "초 후 다시 시도하세요"
                    );
                    return;
                }
            }
        }
        
        filterChain.doFilter(request, response);
    }
}

// 로그인 컨트롤러에서 실패 기록
@RestController
public class SecureLoginController {
    
    @Autowired
    private SlidingWindowRateLimiter rateLimiter;
    
    @Autowired
    private UserService userService;
    
    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginRequest request) {
        // Rate Limiting은 필터에서 확인
        
        User user = userService.findByUsername(request.getUsername());
        
        if (user == null || !passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            // ✅ 로그인 실패 기록 (Rate Limiting 기록됨)
            // 필터 또는 이 메서드에서 이미 recorded됨
            
            return ResponseEntity.status(401).body("자격증명 오류");
        }
        
        return ResponseEntity.ok("로그인 성공");
    }
}
```

### 2. 지수 백오프 (Exponential Backoff)

```java
// ✅ 안전한 코드: Exponential Backoff
@Component
public class ExponentialBackoffRateLimiter {
    
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;
    
    private static final String ATTEMPT_PREFIX = "login_attempt:";
    private static final String BACKOFF_PREFIX = "login_backoff:";
    private static final long INITIAL_DELAY_SECONDS = 1;
    private static final int MAX_BACKOFF_LEVEL = 5;  // 최대 32초 대기
    
    public BackoffResult checkWithBackoff(String username) {
        String attemptKey = ATTEMPT_PREFIX + username;
        String backoffKey = BACKOFF_PREFIX + username;
        
        // ✅ 1. 현재 Backoff 레벨 조회
        Integer backoffLevel = (Integer) redisTemplate.opsForValue().get(backoffKey);
        if (backoffLevel == null) {
            backoffLevel = 0;
        }
        
        // ✅ 2. 대기 시간 계산 (2^backoffLevel 초)
        long delaySeconds = (long) Math.pow(2, backoffLevel);
        
        // ✅ 3. 최대 backoff 레벨 제한
        if (backoffLevel >= MAX_BACKOFF_LEVEL) {
            delaySeconds = (long) Math.pow(2, MAX_BACKOFF_LEVEL);
        }
        
        // ✅ 4. 마지막 시도 시간 조회
        Long lastAttemptTime = (Long) redisTemplate.opsForValue().get(attemptKey);
        long now = System.currentTimeMillis();
        
        if (lastAttemptTime != null) {
            long elapsedSeconds = (now - lastAttemptTime) / 1000;
            
            if (elapsedSeconds < delaySeconds) {
                // 아직 대기 시간이 남음
                return new BackoffResult(
                    false,
                    delaySeconds - elapsedSeconds
                );
            } else {
                // 대기 시간 끝, Backoff 레벨 증가
                backoffLevel++;
                redisTemplate.opsForValue().set(backoffKey, backoffLevel);
            }
        }
        
        // ✅ 5. 시도 시간 업데이트
        redisTemplate.opsForValue().set(attemptKey, now, 86400, TimeUnit.SECONDS);  // 24시간
        
        return new BackoffResult(true, 0);
    }
    
    // 로그인 성공 시 Reset
    public void resetBackoff(String username) {
        String backoffKey = BACKOFF_PREFIX + username;
        String attemptKey = ATTEMPT_PREFIX + username;
        
        redisTemplate.delete(backoffKey);
        redisTemplate.delete(attemptKey);
    }
}

class BackoffResult {
    public boolean allowed;
    public long waitSecondsRemaining;
    
    public BackoffResult(boolean allowed, long waitSecondsRemaining) {
        this.allowed = allowed;
        this.waitSecondsRemaining = waitSecondsRemaining;
    }
}

// 사용 예시
@RestController
public class BackoffLoginController {
    
    @Autowired
    private ExponentialBackoffRateLimiter backoffLimiter;
    
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        String username = request.getUsername();
        
        // ✅ Backoff 확인
        BackoffResult backoffResult = backoffLimiter.checkWithBackoff(username);
        
        if (!backoffResult.allowed) {
            return ResponseEntity
                .status(HttpServletResponse.SC_TOO_MANY_REQUESTS)
                .body(Map.of(
                    "error", "Too many login attempts",
                    "retry_after_seconds", backoffResult.waitSecondsRemaining
                ));
        }
        
        // 인증 로직
        User user = userService.findByUsername(username);
        
        if (user != null && passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            // ✅ 로그인 성공 시 Backoff Reset
            backoffLimiter.resetBackoff(username);
            
            return ResponseEntity.ok("로그인 성공");
        }
        
        // 실패 시 Backoff 계속 증가 (필터에서 처리)
        return ResponseEntity.status(401).body("자격증명 오류");
    }
}
```

### 3. username 기반 Rate Limiting (IP 기반 우회 방지)

```java
// ✅ 안전한 코드: username + IP 조합 Rate Limiting
@Component
public class CompositeRateLimiter {
    
    @Autowired
    private RedisTemplate<String, Long> redisTemplate;
    
    private static final String USERNAME_LIMIT_KEY = "login_username:";
    private static final String IP_LIMIT_KEY = "login_ip:";
    private static final String GLOBAL_LIMIT_KEY = "login_global:";
    
    private static final int USERNAME_MAX_ATTEMPTS = 5;      // 사용자당 5회/분
    private static final int IP_MAX_ATTEMPTS = 50;           // IP당 50회/분
    private static final int GLOBAL_MAX_ATTEMPTS = 10000;    // 전체 1만회/분
    
    private static final long WINDOW_SECONDS = 60;
    
    public CompositeRateLimitResult checkRateLimit(String username, String clientIp) {
        long now = System.currentTimeMillis();
        
        // ✅ 1. username 기반 확인 (가장 엄격)
        String usernameKey = USERNAME_LIMIT_KEY + username;
        if (!checkSlidingWindow(usernameKey, USERNAME_MAX_ATTEMPTS)) {
            return new CompositeRateLimitResult(
                false,
                "Username rate limit exceeded",
                "username"
            );
        }
        
        // ✅ 2. IP 기반 확인 (중간 수준)
        String ipKey = IP_LIMIT_KEY + clientIp;
        if (!checkSlidingWindow(ipKey, IP_MAX_ATTEMPTS)) {
            return new CompositeRateLimitResult(
                false,
                "IP rate limit exceeded",
                "ip"
            );
        }
        
        // ✅ 3. 전역 확인 (느슨한 수준, DDoS 탐지)
        String globalKey = GLOBAL_LIMIT_KEY;
        if (!checkSlidingWindow(globalKey, GLOBAL_MAX_ATTEMPTS)) {
            // 심각한 상황: 경고 발송, 관리자 알림
            logSecurityAlert("Global rate limit exceeded", clientIp);
            return new CompositeRateLimitResult(
                false,
                "Service overloaded",
                "global"
            );
        }
        
        return new CompositeRateLimitResult(true, null, null);
    }
    
    private boolean checkSlidingWindow(String key, int maxAttempts) {
        long now = System.currentTimeMillis();
        long windowStart = now - (WINDOW_SECONDS * 1000);
        
        // 윈도우 범위 밖의 데이터 삭제
        redisTemplate.opsForZSet().removeRangeByScore(key, 0, windowStart);
        
        // 현재 윈도우 내의 시도 횟수
        long count = redisTemplate.opsForZSet().size(key);
        
        if (count >= maxAttempts) {
            return false;
        }
        
        // 현재 시도 기록
        redisTemplate.opsForZSet().add(key, now, now);
        redisTemplate.expire(key, WINDOW_SECONDS, TimeUnit.SECONDS);
        
        return true;
    }
    
    private void logSecurityAlert(String message, String clientIp) {
        // 보안팀에 알림 (이메일, Slack 등)
        System.err.println("[SECURITY ALERT] " + message + " from " + clientIp);
    }
}

class CompositeRateLimitResult {
    public boolean allowed;
    public String message;
    public String limitType;  // "username", "ip", "global"
    
    public CompositeRateLimitResult(boolean allowed, String message, String limitType) {
        this.allowed = allowed;
        this.message = message;
        this.limitType = limitType;
    }
}

// 필터에서 사용
@Component
public class CompositeRateLimitFilter extends OncePerRequestFilter {
    
    @Autowired
    private CompositeRateLimiter rateLimiter;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        
        if (request.getRequestURI().equals("/login")) {
            String username = extractUsername(request);
            String clientIp = getClientIp(request);
            
            CompositeRateLimitResult result = rateLimiter.checkRateLimit(username, clientIp);
            
            if (!result.allowed) {
                response.setStatus(HttpServletResponse.SC_TOO_MANY_REQUESTS);
                response.getWriter().write(
                    Map.of(
                        "error", result.message,
                        "limit_type", result.limitType
                    ).toString()
                );
                return;
            }
        }
        
        filterChain.doFilter(request, response);
    }
    
    private String getClientIp(HttpServletRequest request) {
        String xForwarded = request.getHeader("X-Forwarded-For");
        if (xForwarded != null && !xForwarded.isEmpty()) {
            return xForwarded.split(",")[0];
        }
        return request.getRemoteAddr();
    }
}
```

### 4. 계정 잠금 vs 일시적 잠금 (DoS 방어)

```java
// ✅ 안전한 코드: 일시적 잠금 (계정 잠금 DoS 방지)
@Service
public class SecureAccountLockService {
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private RedisTemplate<String, String> redisTemplate;
    
    private static final int FAILED_ATTEMPTS_THRESHOLD = 5;
    private static final long TEMPORARY_LOCK_DURATION = 15 * 60;  // 15분
    private static final String TEMP_LOCK_PREFIX = "account_temp_lock:";
    
    public void recordFailedLogin(String username) {
        User user = userRepository.findByUsername(username).orElse(null);
        
        if (user != null) {
            // ✅ 1. 임시 잠금 확인
            if (isTemporarilyLocked(username)) {
                // 이미 임시 잠금 상태 (일시적 잠금만 연장, 영구 잠금 X)
                return;
            }
            
            user.incrementFailedLoginAttempts();
            
            // ✅ 2. FAILED_ATTEMPTS_THRESHOLD 도달 시 임시 잠금
            if (user.getFailedLoginAttempts() >= FAILED_ATTEMPTS_THRESHOLD) {
                // 영구 잠금 대신 일시적 잠금
                lockAccountTemporarily(username);
                
                // ✅ 3. 사용자에게 알림 (의심 활동)
                notifyUser(user, "계정에 여러 번의 실패한 로그인 시도가 감지되었습니다");
            }
            
            userRepository.save(user);
        }
    }
    
    public void recordSuccessfulLogin(String username) {
        User user = userRepository.findByUsername(username).orElse(null);
        
        if (user != null) {
            // ✅ 로그인 성공 시 실패 카운트 리셋
            user.setFailedLoginAttempts(0);
            userRepository.save(user);
            
            // ✅ 임시 잠금도 제거
            removeTemporaryLock(username);
        }
    }
    
    private void lockAccountTemporarily(String username) {
        String key = TEMP_LOCK_PREFIX + username;
        redisTemplate.opsForValue().set(
            key,
            "locked",
            TEMPORARY_LOCK_DURATION,
            TimeUnit.SECONDS
        );
    }
    
    private boolean isTemporarilyLocked(String username) {
        String key = TEMP_LOCK_PREFIX + username;
        return redisTemplate.hasKey(key);
    }
    
    private void removeTemporaryLock(String username) {
        String key = TEMP_LOCK_PREFIX + username;
        redisTemplate.delete(key);
    }
    
    private void notifyUser(User user, String message) {
        // 이메일 발송
        emailService.sendSecurityAlert(user.getEmail(), message);
    }
}

// 로그인 컨트롤러에서 사용
@RestController
public class SecureLoginWithAccountLockController {
    
    @Autowired
    private SecureAccountLockService accountLockService;
    
    @Autowired
    private UserService userService;
    
    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginRequest request) {
        String username = request.getUsername();
        User user = userService.findByUsername(username);
        
        // ✅ 1. 임시 잠금 확인
        if (accountLockService.isTemporarilyLocked(username)) {
            return ResponseEntity
                .status(403)
                .body("계정이 일시적으로 잠금되었습니다. 15분 후 다시 시도하세요.");
        }
        
        // ✅ 2. 인증 시도
        if (user != null && passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            // 로그인 성공
            accountLockService.recordSuccessfulLogin(username);
            return ResponseEntity.ok("로그인 성공");
        }
        
        // ✅ 3. 실패 기록
        accountLockService.recordFailedLogin(username);
        return ResponseEntity.status(401).body("자격증명 오류");
    }
}
```

## 🔬 공격 원리 분석 (공격자 관점의 내부 동작)

### 브루트포스 공격의 단계별 진행

```
Step 1: 타겟 선정
├─ 공격자가 공격할 서비스 선택 (예: 온라인 뱅킹)
├─ 일반적인 사용자 이름 목록 준비
└─ 예: admin, user1, john_doe, target@example.com 등

Step 2: 비밀번호 목록 준비
├─ 공개 단어장 다운로드 (rockyou.txt: 14백만 단어)
├─ 유출된 비밀번호 DB 구입 (Darknet에서)
├─ 또는 규칙 기반 생성 (Password123, January2024 등)
└─ 결과: 수백만 개의 후보 비밀번호

Step 3: Rate Limiting 없을 때
├─ 공격자가 자동화 스크립트 실행
├─ for password in passwords:
├─     POST /login
├─     username=target
├─     password=password
├─     if status == 200: found password!
└─ 속도: 초당 1,000~10,000개 시도 가능

Step 4: 계산
├─ 비밀번호 1,000,000개
├─ 속도 1,000개/초
├─ 필요 시간: 1,000초 = 약 17분
└─ 결과: 17분 안에 비밀번호 발견 가능

Step 5: 공격 성공
├─ 비밀번호 알아냄: password123
├─ 계정 접근: session_token 획득
├─ 개인정보 탈취: 주소, 전화번호, SSN 등
├─ 금융 정보 탈취: 신용카드, 계좌번호
└─ 또는 계정을 판매하거나 몸값 요구
```

### Rate Limiting으로 방어되는 방식

```
┌──────────────────────────────────┐
│ Rate Limiting 없음 (취약)          │
├──────────────────────────────────┤
│ 시간: 0초                         │
│ username: target                  │
│ password: password1               │
│ → 401 Unauthorized                │
│                                   │
│ 시간: 0.1초                       │
│ password: password2               │
│ → 401 Unauthorized                │
│                                   │
│ ... (무제한 시도 계속)             │
│                                   │
│ 시간: 300초 (5분)                 │
│ password: password123             │
│ → 200 OK (공격 성공!)              │
└──────────────────────────────────┘

┌──────────────────────────────────┐
│ Rate Limiting 있음 (username 기반)│
├──────────────────────────────────┤
│ 시간: 0초                         │
│ 시도 1/5                          │
│ → 401 Unauthorized                │
│                                   │
│ 시간: 0.1초                       │
│ 시도 2/5                          │
│ → 401 Unauthorized                │
│                                   │
│ 시간: 0.5초                       │
│ 시도 5/5                          │
│ → 401 Unauthorized                │
│                                   │
│ 시간: 0.6초 (아직 60초 윈도우 내)   │
│ 시도 6/5                          │
│ → 429 Too Many Requests           │
│ Retry-After: 55초                 │
│                                   │
│ (다른 IP로 우회 시도해도 username   │
│  기반 제한으로 보호됨)              │
└──────────────────────────────────┘
```

## 💻 실전 실험 (취약점 재현 → 공격 → 방어 검증)

### 실험 1: 브루트포스 공격 시뮬레이션

```java
@SpringBootTest
public class BruteForceAttackTest {
    
    @Autowired
    private MockMvc mockMvc;
    
    @Test
    public void testBruteForceWithoutRateLimit() throws Exception {
        // ❌ Rate Limiting 없으면 모든 시도 성공
        String[] passwords = {"password1", "password2", "correct_password"};
        
        for (String password : passwords) {
            MvcResult result = mockMvc.perform(
                post("/login")
                    .param("username", "target_user")
                    .param("password", password)
            )
                .andReturn();
            
            if (result.getResponse().getStatus() == 200) {
                System.out.println("[+] 비밀번호 발견: " + password);
                break;
            }
        }
    }
    
    @Test
    public void testBruteForceWithRateLimit() throws Exception {
        // ✅ Rate Limiting이 있으면 일부만 성공, 후속 시도는 차단
        String[] passwords = {"password1", "password2", "password3", 
                              "password4", "password5", "correct_password"};
        
        int blockedCount = 0;
        for (String password : passwords) {
            MvcResult result = mockMvc.perform(
                post("/login")
                    .param("username", "target_user")
                    .param("password", password)
            )
                .andReturn();
            
            int status = result.getResponse().getStatus();
            
            if (status == 429) {  // Too Many Requests
                System.out.println("[-] Rate limit 도달");
                blockedCount++;
            }
        }
        
        // ✅ 대부분의 시도가 차단됨
        assertTrue(blockedCount > 0);
    }
}
```

### 실험 2: username 기반 vs IP 기반 Rate Limiting

```java
@SpringBootTest
public class RateLimiterComparisonTest {
    
    @Test
    public void testIpBasedRateLimitCanBeBypassedWithProxies() {
        // IP 기반 Rate Limiting은 프록시로 우회 가능
        String[] ips = {
            "192.168.1.1",
            "192.168.1.2",
            "192.168.1.3",
            "192.168.1.4",
            "192.168.1.5"
        };
        
        // IP 1: 5회 시도 → 차단
        // IP 2: 5회 시도 → 차단
        // IP 3: 5회 시도 → 차단
        // ...
        // 모두 다른 IP로 우회 가능
    }
    
    @Test
    public void testUsernameBasedRateLimitCannotBeBypassedWithProxies() {
        // username 기반 Rate Limiting은 프록시로 우회 불가능
        // target_user 5회 시도 → 차단
        // 아무리 많은 프록시를 사용해도 target_user 이름은 같음
        // 따라서 15분 동안 모든 시도가 차단됨
    }
}
```

### 실험 3: 계정 잠금 DoS 방어

```java
@SpringBootTest
public class AccountLockDoSTest {
    
    @Test
    public void testTemporaryLockPreventsDos() throws Exception {
        // ✅ 임시 잠금 (15분): DoS 공격이 제한됨
        // 공격자가 john_doe 계정을 5번 잠금
        // john_doe: 15분 동안 로그인 불가
        // 15분 후: 자동으로 잠금 해제
        // john_doe가 정상 비밀번호로 로그인 가능
        
        String username = "john_doe";
        String correctPassword = "secure_password_123";
        
        // 1. 공격자가 5번 실패 시도
        for (int i = 0; i < 5; i++) {
            mockMvc.perform(
                post("/login")
                    .param("username", username)
                    .param("password", "wrong")
            );
        }
        
        // 2. 정상 사용자가 로그인 시도
        MvcResult result = mockMvc.perform(
            post("/login")
                .param("username", username)
                .param("password", correctPassword)
        )
            .andExpect(status().isForbidden())  // 임시 잠금됨
            .andReturn();
        
        String response = result.getResponse().getContentAsString();
        assertTrue(response.contains("일시적으로 잠금"));
        
        // 3. 15분 후 자동 해제
        Thread.sleep(TEMPORARY_LOCK_DURATION);
        
        // 4. 다시 시도
        mockMvc.perform(
            post("/login")
                .param("username", username)
                .param("password", correctPassword)
        )
            .andExpect(status().isOk());  // 성공
    }
}
```

## 📊 공격 성공 조건 vs 방어 성공 조건 비교

| 항목 | 공격 성공 조건 | 방어 성공 조건 |
|------|--------------|--------------|
| **Rate Limiting** | 없음 | username 기반 5회/분 |
| **한계 극복** | IP 변경 (프록시) | username 기반 (IP 무관) |
| **계정 잠금** | 없음 (무제한 시도) | 5회 실패 후 임시 잠금 |
| **DoS 공격** | 계정 잠금 없으면 무관 | 임시 잠금 (영구 X) |
| **Backoff** | 없음 (즉시 재시도) | Exponential (2^n 초) |
| **모니터링** | 없음 | 이상 탐지 + 알림 |

## ⚖️ 트레이드오프 (보안 강화 vs 사용성/성능)

### 1. Rate Limit 강도 vs 정상 사용자 편의
- **보안**: username당 1회/분 (매우 강함)
- **사용성**: 비밀번호 한 번 틀리면 1분 대기
- **트레이드오프**: username당 5회/분 (합리적 수준)

### 2. 임시 잠금 기간 vs 공격자 재시도 가능성
- **보안**: 24시간 잠금 (공격자 재시도 불가)
- **사용성**: 정상 사용자가 하루 잠금 (불편)
- **트레이드오프**: 15분 잠금 + 사용자 알림 (합리적)

### 3. username 기반 vs IP 기반 vs 조합
- **보안**: username 기반 (우회 불가)
- **성능**: 데이터 저장 필요, 조회 시간 증가
- **트레이드오프**: username + IP + Global 조합 사용

### 4. 실시간 모니터링 vs 성능
- **보안**: 모든 로그인 시도 실시간 분석
- **성능**: 데이터베이스/로그 저장소 부하 증가
- **트레이드오프**: 샘플링 또는 의심 활동만 기록

## 📌 핵심 정리

1. **username 기반 Rate Limiting**
   ```java
   SlidingWindowRateLimiter: 5회/분 (username 기반)
   ```

2. **임시 잠금 (영구 잠금 X)**
   ```java
   5회 실패 → 15분 임시 잠금
   로그인 성공 → 자동 해제
   ```

3. **Exponential Backoff**
   ```java
   1초, 2초, 4초, 8초, 16초, 32초 (최대)
   ```

4. **복합 Rate Limiting**
   ```java
   username: 5/분
   IP: 50/분
   Global: 10,000/분
   ```

5. **보안 모니터링**
   ```java
   로그인 실패 기록
   의심 활동 감지
   사용자/관리자 알림
   ```

## 🤔 생각해볼 문제 (+ 해설)

### 문제 1: CAPTCHA를 추가하면 브루트포스를 완전히 방어할 수 있는가?
**해설:**
- 이론적으로는 맞음 (자동화된 공격 불가)
- 하지만 현실의 문제:
  - CAPTCHA를 깨는 AI가 존재 (특히 reCAPTCHA v2)
  - 사용자 경험 저하 (매번 CAPTCHA 풀어야 함)
  - 접근성 문제 (시각 장애인)
- **최선의 방법**:
  - Rate Limiting + 임시 잠금 + CAPTCHA 조합
  - 처음 1-2회 실패: 아무것도 안함
  - 3-5회 실패: CAPTCHA 추가
  - 6회 이상: 임시 잠금

### 문제 2: 계정 잠금 기능은 왜 위험한가?
**해설:**
- 공격자가 의도적으로 다른 사용자를 잠금 (DoS)
- 예: 회사 CEO의 계정을 반복 잠금
- CEO가 중요한 업무를 수행해야 하는데 로그인 불가
- **따라서 계정 잠금은 사용하면 안됨** (또는 부분 기능만)
- 대신 **임시 잠금** (15분 자동 해제) 사용

### 문제 3: Rate Limiting을 account + IP 조합으로 하면 더 좋은가?
**해설:**
- username 기반: 강함, IP 변경으로 우회 불가
- IP 기반: 약함, 프록시로 우회 가능
- 조합: 가장 좋음
  - username 5회/분: 개별 계정 보호
  - IP 50회/분: 봇넷 감지
  - Global 10,000회/분: DDoS 감지
- 하지만 관리 복잡도 증가

---

<div align="center">

**[⬅️ 이전: OAuth2 취약점](./05-oauth2-vulnerabilities.md)** | **[홈으로 🏠](../README.md)** | **[다음: 비밀번호 저장 ➡️](./07-password-storage.md)**

</div>
