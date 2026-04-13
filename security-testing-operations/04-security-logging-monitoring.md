# 보안 로깅과 모니터링

---

## 🎯 핵심 질문

- **보안 이벤트 로그란 무엇인가?** 인증 시도, 권한 변경, 민감 데이터 접근 등을 기록합니다.
- **Spring AOP로 로깅을 어떻게 자동화하는가?** 어노테이션으로 민감한 메서드를 표시하면 자동으로 로깅합니다.
- **비정상 패턴이란?** 짧은 시간에 많은 실패 로그인, IDOR 시도 등입니다.
- **로그 탬퍼링을 어떻게 방지하는가?** 중앙 집중 로그, 불변 저장소, 암호 서명을 사용합니다.

---

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

### Equifax 침해 사건 (2017) — 로깅 미실시
**배경**: 공격자가 3개월간 데이터를 탈취했지만, 로깅이 없어 언제 어디서 침입했는지 추적 불가능.

**결과**:
```
1. 침입 시간 파악 불가능
   → 영향받은 데이터 범위 추정 어려움

2. 침입 경로 파악 불가능
   → 같은 취약점으로 다시 공격받을 수 있음

3. 감사 추적 불가능
   → 규제 기관의 요구사항 미충족

4. 피해:
   - 7억 달러 합의금
   - 신뢰도 완전 상실
   - 규제 강화
```

---

## 😱 취약한 코드/설정 (Before — 로깅 없음)

### 취약 1: 보안 이벤트 로깅 부재

```java
@Service
public class InsecureUserService {

    // ❌ 위험: 로그인 시도를 기록하지 않음
    public ResponseEntity<?> login(String username, String password) {
        User user = userRepository.findByUsername(username);
        
        if (user == null || !passwordEncoder.matches(password, user.getPasswordHash())) {
            return ResponseEntity.status(401).build();  // 실패만 처리, 로깅 안 함
        }
        
        // ❌ 위험: 누가 언제 로그인했는지 기록 없음
        return ResponseEntity.ok(generateToken(user));
    }

    // ❌ 위험: 권한 변경을 로깅하지 않음
    public void grantAdminRole(Long userId) {
        User user = userRepository.findById(userId).orElseThrow();
        user.addRole(Role.ADMIN);
        userRepository.save(user);
        // 누가 언제 관리자 권한을 줬는지 기록 없음
    }

    // ❌ 위험: 민감한 데이터 접근을 로깅하지 않음
    public List<User> getAllUsers() {
        return userRepository.findAll();  // 모든 사용자 데이터 조회
        // 누가 전체 사용자 정보에 접근했는지 기록 없음
    }

    // ❌ 위험: 예외 발생 시에도 로깅 최소화
    public void processPayment(Payment payment) {
        try {
            // 결제 처리
        } catch (Exception e) {
            // 간단한 에러만 기록
            logger.error("Payment failed");
            // 실패 이유, 시간, 사용자 등 정보 부족
        }
    }
}
```

### 취약 2: 일반 로그에 민감 정보 혼재

```yaml
# ❌ 위험: 모든 요청을 기록하되 민감 정보 구분 안 함
logging:
  level:
    root: DEBUG
    
# 로그 결과:
# [DEBUG] Incoming request: GET /api/users/1/profile
# [DEBUG] Request headers: {Authorization: Bearer token123, Cookie: JSESSIONID=abc}
# [DEBUG] Request body: {"ssn": "123-45-6789", "credit_card": "4532-1234-5678-9012"}
# [DEBUG] Response: {"id": 1, "name": "Alice", "ssn": "123-45-6789"}
# → 민감 정보가 일반 로그에 기록됨
```

---

## ✨ 방어 코드/설정 (After — 종합 보안 로깅)

### 방어 1: Spring AOP를 이용한 자동 보안 로깅

```java
// 보안 이벤트 어노테이션
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface SecurityEvent {
    String action();  // "LOGIN", "AUTHORIZE", "DATA_ACCESS" 등
    String resourceType() default "";
    boolean logResult() default true;
}

// 보안 로깅 AOP
@Component
@Aspect
public class SecurityLoggingAspect {

    private static final Logger securityLogger = 
        LoggerFactory.getLogger("SECURITY");

    @Around("@annotation(securityEvent)")
    public Object logSecurityEvent(ProceedingJoinPoint joinPoint, 
                                   SecurityEvent securityEvent) throws Throwable {
        
        // 1. 요청 정보 수집
        String methodName = joinPoint.getSignature().getName();
        String action = securityEvent.action();
        String resourceType = securityEvent.resourceType();
        
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth != null ? auth.getName() : "ANONYMOUS";
        
        String clientIp = getClientIp();
        long startTime = System.currentTimeMillis();
        
        // 2. 메서드 실행 전 로깅
        securityLogger.info("SECURITY_EVENT_START | " +
            "action={} | " +
            "user={} | " +
            "method={} | " +
            "ip={} | " +
            "timestamp={}",
            action, username, methodName, clientIp, startTime);
        
        Object result = null;
        boolean success = true;
        String errorMessage = null;
        
        try {
            // 3. 실제 메서드 실행
            result = joinPoint.proceed();
            return result;
            
        } catch (Exception e) {
            success = false;
            errorMessage = e.getClass().getSimpleName();
            
            // 예외 로깅
            securityLogger.warn("SECURITY_EVENT_FAILED | " +
                "action={} | " +
                "user={} | " +
                "method={} | " +
                "error={} | " +
                "ip={}",
                action, username, methodName, errorMessage, clientIp);
            
            throw e;
            
        } finally {
            // 4. 실행 후 종합 로깅
            long duration = System.currentTimeMillis() - startTime;
            
            securityLogger.info("SECURITY_EVENT_END | " +
                "action={} | " +
                "user={} | " +
                "method={} | " +
                "success={} | " +
                "duration={}ms | " +
                "resourceType={} | " +
                "ip={}",
                action, username, methodName, success, duration, resourceType, clientIp);
        }
    }

    private String getClientIp() {
        ServletRequestAttributes attrs = 
            (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attrs == null) return "UNKNOWN";
        
        HttpServletRequest request = attrs.getRequest();
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty()) {
            ip = request.getRemoteAddr();
        }
        return ip;
    }
}

// 사용 예시
@Service
public class SecureUserService {

    // ✅ 로그인 보안 로깅
    @SecurityEvent(action = "LOGIN", resourceType = "USER_ACCOUNT")
    public ResponseEntity<?> login(String username, String password) {
        User user = userRepository.findByUsername(username);
        
        if (user == null || !passwordEncoder.matches(password, user.getPasswordHash())) {
            // 실패 로그는 AOP에서 자동 기록
            throw new AuthenticationException("Invalid credentials");
        }
        
        // 성공 로그도 자동 기록
        return ResponseEntity.ok(generateToken(user));
    }

    // ✅ 권한 변경 보안 로깅
    @SecurityEvent(action = "GRANT_ROLE", resourceType = "USER_PERMISSION")
    public void grantAdminRole(Long userId) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new EntityNotFoundException("User not found"));
        
        user.addRole(Role.ADMIN);
        userRepository.save(user);
        // AOP가 자동으로 "누가 언제 어떤 사용자에게 ADMIN 권한을 줬는지" 기록
    }

    // ✅ 민감 데이터 접근 로깅
    @SecurityEvent(action = "DATA_ACCESS", resourceType = "PII")
    public List<UserDetailDto> exportAllUserDetails() {
        return userRepository.findAll().stream()
            .map(UserDetailDto::from)
            .toList();
        // AOP가 자동으로 "누가 언제 모든 사용자 개인정보에 접근했는지" 기록
    }

    // ✅ 데이터 수정 로깅
    @SecurityEvent(action = "DATA_MODIFICATION", resourceType = "USER_DATA")
    public void updateUserEmail(Long userId, String newEmail) {
        User user = userRepository.findById(userId).orElseThrow();
        String oldEmail = user.getEmail();
        user.setEmail(newEmail);
        userRepository.save(user);
        // AOP가 "oldEmail → newEmail" 변경 기록
    }
}
```

### 방어 2: 비정상 패턴 감지

```java
@Component
public class AnomalyDetectionService {

    @Autowired
    private SecurityEventRepository eventRepository;
    private static final Logger alertLogger = LoggerFactory.getLogger("SECURITY_ALERT");

    // ✅ 브루트포스 공격 감지 (1분에 5회 이상 실패)
    public void detectBruteForce(String username, String clientIp) {
        long oneMinuteAgo = System.currentTimeMillis() - 60000;
        
        List<SecurityEvent> recentFailures = eventRepository
            .findByUsernameAndActionAndTimestampAfter(
                username, "LOGIN_FAILED", oneMinuteAgo);
        
        if (recentFailures.size() >= 5) {
            alertLogger.error("ALERT_BRUTE_FORCE | " +
                "user={} | " +
                "ip={} | " +
                "attempts={} | " +
                "action=ACCOUNT_LOCKED",
                username, clientIp, recentFailures.size());
            
            // 계정 일시 잠금 (15분)
            userService.lockAccount(username, 15 * 60);
        }
    }

    // ✅ IDOR 공격 감지 (다른 사용자 데이터 접근 시도 반복)
    public void detectIdorAttempts(String username, String clientIp) {
        long fiveMinutesAgo = System.currentTimeMillis() - 300000;
        
        List<SecurityEvent> accessDeniedEvents = eventRepository
            .findByUsernameAndActionAndTimestampAfter(
                username, "ACCESS_DENIED", fiveMinutesAgo);
        
        if (accessDeniedEvents.size() >= 10) {  // 5분에 10회 이상 거부
            alertLogger.warn("ALERT_IDOR_ATTEMPT | " +
                "user={} | " +
                "ip={} | " +
                "attempts={}",
                username, clientIp, accessDeniedEvents.size());
            
            // 추가 인증 요구 또는 세션 무효화
            sessionManager.invalidateUserSessions(username);
        }
    }

    // ✅ 비정상 접근 시간 감지
    public void detectAnomalousAccessTime(String username, String clientIp) {
        LocalDateTime lastLogin = userService.getLastLoginTime(username);
        LocalDateTime now = LocalDateTime.now();
        
        // 평소 9-5시에 접근하던 사용자가 새벽 3시에 접근
        if (lastLogin != null && 
            isWithinBusinessHours(lastLogin) && 
            !isWithinBusinessHours(now)) {
            
            alertLogger.warn("ALERT_ANOMALOUS_TIME | " +
                "user={} | " +
                "lastLogin={} | " +
                "currentTime={} | " +
                "ip={}",
                username, lastLogin, now, clientIp);
        }
    }

    // ✅ 지역 변경 감지 (IP 지리적 위치 변화)
    public void detectLocationChange(String username, String newIp) {
        String lastIp = userService.getLastLoginIp(username);
        
        if (lastIp != null) {
            String lastCountry = getCountryFromIp(lastIp);
            String newCountry = getCountryFromIp(newIp);
            
            if (!lastCountry.equals(newCountry)) {
                alertLogger.warn("ALERT_LOCATION_CHANGE | " +
                    "user={} | " +
                    "from={} | " +
                    "to={} | " +
                    "action=REQUEST_VERIFICATION",
                    username, lastCountry, newCountry);
                
                // 추가 검증 요구 (이메일, SMS)
                verificationService.requestEmailVerification(username);
            }
        }
    }

    private boolean isWithinBusinessHours(LocalDateTime dateTime) {
        int hour = dateTime.getHour();
        return hour >= 9 && hour < 17;
    }

    private String getCountryFromIp(String ip) {
        // MaxMind GeoIP2 API 사용
        return geoIpService.getCountry(ip);
    }
}
```

### 방어 3: ELK Stack 로그 수집

```yaml
# logback-spring.xml (Logback 설정)
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <!-- 파일 로그 (JSON 포맷) -->
    <appender name="SECURITY_FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <file>logs/security.log</file>
        <encoder class="net.logstash.logback.encoder.LogstashEncoder">
            <customFields>{"environment":"${app.environment}", "service":"${app.name}"}</customFields>
        </encoder>
        <rollingPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy">
            <fileNamePattern>logs/security-%d{yyyy-MM-dd}-%i.log.gz</fileNamePattern>
            <maxFileSize>100MB</maxFileSize>
            <maxHistory>30</maxHistory>
        </rollingPolicy>
    </appender>

    <!-- Elasticsearch로 전송 (ELK Stack) -->
    <appender name="ELASTICSEARCH" class="com.internetwidgetware.logback.ch.qos.logback.core.rolling.RollingFileAppender">
        <encoder class="net.logstash.logback.encoder.LogstashEncoder">
            <providers>
                <timestamp>
                    <timeZone>UTC</timeZone>
                </timestamp>
                <logLevel/>
                <loggerName/>
                <message/>
            </providers>
        </encoder>
    </appender>

    <!-- 보안 이벤트 로거 -->
    <logger name="SECURITY" level="INFO">
        <appender-ref ref="SECURITY_FILE"/>
    </logger>

    <logger name="SECURITY_ALERT" level="WARN">
        <appender-ref ref="SECURITY_FILE"/>
    </logger>

    <root level="INFO">
        <appender-ref ref="SECURITY_FILE"/>
    </root>
</configuration>
```

**Elasticsearch 쿼리** (비정상 활동 탐색):
```json
# 1시간 내 로그인 실패 5회 이상
GET security-logs-*/_search
{
  "query": {
    "bool": {
      "must": [
        {"match": {"action": "LOGIN_FAILED"}},
        {"range": {"@timestamp": {"gte": "now-1h"}}}
      ],
      "filter": [
        {"term": {"username": "alice"}}
      ]
    }
  },
  "aggs": {
    "failure_count": {
      "terms": {"field": "username"}
    }
  }
}

# 결과:
# {
#   "aggregations": {
#     "failure_count": {
#       "buckets": [
#         {"key": "alice", "doc_count": 7}  # 7회 실패!
#       ]
#     }
#   }
# }
```

### 방어 4: CloudWatch Logs (AWS)

```java
@Configuration
public class CloudWatchLogConfig {

    @Bean
    public AWSLogs awsLogs() {
        return AWSLogsClientBuilder.standard()
            .withRegion(Regions.US_EAST_1)
            .build();
    }

    @Bean
    public CloudWatchAppender cloudWatchAppender(AWSLogs awsLogs) {
        CloudWatchAppender appender = new CloudWatchAppender();
        appender.setLogGroupName("/aws/app/security");
        appender.setLogStreamName("app-security-events");
        appender.setAwsLogs(awsLogs);
        return appender;
    }
}

// CloudWatch에서 비정상 활동 감지 (Lambda)
public class AnomalyDetectionLambda implements RequestHandler<CloudWatchLogsEvent, Void> {

    @Override
    public Void handleRequest(CloudWatchLogsEvent event, Context context) {
        // 로그 데이터 디코딩
        String logData = decompress(event.getAwsLogs().getData());
        
        // JSON 파싱
        JSONObject json = new JSONObject(logData);
        JSONArray logEvents = json.getJSONArray("logEvents");
        
        for (int i = 0; i < logEvents.length(); i++) {
            JSONObject logEvent = logEvents.getJSONObject(i);
            String message = logEvent.getString("message");
            
            // 비정상 패턴 감지
            if (message.contains("ALERT_BRUTE_FORCE")) {
                // SNS 알림 발송
                sendAlert("Brute force attack detected!");
            }
        }
        
        return null;
    }
}
```

### 방어 5: 로그 무결성 보장

```java
@Component
public class LogIntegrityService {

    @Autowired
    private SecurityEventRepository eventRepository;

    // ✅ 로그 서명 (HMAC-SHA256)
    public String signLogEvent(SecurityEvent event) {
        String eventData = event.toString();
        String key = getSigningKey();  // 비밀 키 (환경변수)
        
        return hmacSha256(eventData, key);
    }

    // ✅ 로그 검증
    public boolean verifyLogIntegrity(SecurityEvent event, String signature) {
        String expectedSignature = signLogEvent(event);
        return MessageDigest.isEqual(
            signature.getBytes(StandardCharsets.UTF_8),
            expectedSignature.getBytes(StandardCharsets.UTF_8)
        );
    }

    // ✅ 체인 검증 (블록체인 방식)
    public void createAuditChain(List<SecurityEvent> events) {
        String previousHash = "START";
        
        for (SecurityEvent event : events) {
            String currentHash = calculateHash(previousHash + event.toString());
            event.setChainHash(currentHash);
            eventRepository.save(event);
            previousHash = currentHash;
        }
    }

    private String hmacSha256(String data, String key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(
                key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(keySpec);
            
            byte[] result = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(result);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String calculateHash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
```

---

## 📌 핵심 정리

1. **보안 로깅은 필수**: 인증, 권한, 데이터 접근 모두 기록
2. **Spring AOP 자동화**: 어노테이션으로 선언적 로깅
3. **비정상 패턴 감지**: 브루트포스, IDOR 시도, 지역 변경 등
4. **중앙 집중식**: ELK Stack 또는 CloudWatch로 로그 수집
5. **로그 무결성**: HMAC 서명, 체인 해싱으로 탬퍼링 방지
6. **고급 분석**: Elasticsearch 쿼리로 침해 사고 추적

---

## 🤔 생각해볼 문제 (+ 해설)

### Q1. 모든 메서드를 로깅하면 성능 영향이 크지 않은가?
**해설**: AOP는 비동기 로깅으로 메인 스레드를 블로킹하지 않으므로 영향 최소화. 중요한 보안 이벤트만 선택적 로깅.

### Q2. 로그 저장 비용이 많이 들지 않는가?
**해설**: ELK Stack에서 인덱싱, 압축, 자동 삭제(30일)로 비용 관리. 또는 AWS S3에 저가 저장.

<div align="center">

**[⬅️ 이전: 침투 테스트 방법론](./03-penetration-testing.md)** | **[홈으로 🏠](../README.md)** | **[다음: 인시던트 대응 ➡️](./05-incident-response.md)**

</div>
