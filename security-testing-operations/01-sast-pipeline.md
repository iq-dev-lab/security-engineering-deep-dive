# SAST 자동화 — 코드 정적 분석

---

## 🎯 핵심 질문

- **SAST(Static Application Security Testing)가 무엇인가?** 소스 코드를 실행하지 않고 정적으로 분석하여 보안 취약점을 탐지합니다.
- **SpotBugs와 SonarQube의 차이는?** SpotBugs는 버그 패턴 탐지, SonarQube는 보안/코드 품질 종합 분석입니다.
- **GitHub Actions에서 SAST 게이트를 구현하려면?** 취약점 발견 시 PR을 자동으로 차단합니다.
- **Gitleaks는 언제 실행해야 하는가?** 모든 커밋 전에, pre-commit 훅이나 CI/CD 파이프라인에서 실행합니다.

---

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

### Capital One (2019) — 자동 테스트 미실시
**배경**: WAF 규칙에서 발생한 예외를 로깅했는데, 예외 메시지에 민감한 데이터가 포함되었습니다.

**문제점**:
```java
// 검사되지 않은 코드:
logger.error("WAF exception: {}", exception.getMessage());
// → 데이터베이스 쿼리 에러 메시지에 고객 ID, SQL 포함

// SpotBugs나 SonarQube가 있었다면:
// [BUG] Sensitive data exposure in log message
// → 자동으로 탐지 가능
```

**결과**: 자동화된 정적 분석 투자로 사전 탐지 가능했던 취약점

---

## 😱 취약한 코드/설정 (Before — 원리를 모를 때의 구현)

### 취약 1: SAST 도구 미사용

```gradle
// ❌ 위험: build.gradle에 보안 플러그인 없음
plugins {
    id 'java'
    id 'org.springframework.boot' version '3.2.0'
}

dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web'
}

// gradle build 실행해도 보안 취약점 전혀 검사 안 함
// 개발자가 코드 리뷰로만 의존
```

### 취약 2: SQL 인젝션 탐지 안 됨

```java
@Service
public class UserService {

    // ❌ 위험: 사용자 입력을 직접 SQL에 포함
    public List<User> searchUsers(String searchTerm) {
        String sql = "SELECT * FROM users WHERE name = '" + searchTerm + "'";
        // SAST 도구 없으면 이 취약점을 자동으로 감지하지 않음
        return jdbcTemplate.query(sql, new UserRowMapper());
    }

    // ❌ 위험: PreparedStatement 미사용
    public User findUserById(Long id) {
        String sql = "SELECT * FROM users WHERE id = " + id;  // 정수지만 마찬가지
        return jdbcTemplate.queryForObject(sql, new UserRowMapper());
    }
}
```

### 취약 3: 예외 정보 노출

```java
@RestControllerAdvice
public class GlobalExceptionHandler {

    // ❌ 위험: 스택 트레이스를 응답에 포함
    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleException(Exception e) {
        Map<String, Object> response = new HashMap<>();
        response.put("error", e.getMessage());
        response.put("stackTrace", e.getStackTrace());  // ❌ 직접 노출
        
        return ResponseEntity.status(500).body(response);
    }
}

// SAST가 탐지할 수 있는 패턴:
// - exception.getStackTrace() 사용
// - exception.getCause()를 응답에 포함
// - printStackTrace() 호출
```

### 취약 4: 하드코딩된 비밀번호

```java
@Configuration
public class DatabaseConfig {

    @Bean
    public DataSource dataSource() {
        // ❌ 위험: 비밀번호가 소스 코드에 하드코딩
        return DataSourceBuilder.create()
            .url("jdbc:postgresql://prod-db.internal:5432/users")
            .username("admin")
            .password("SuperSecretPassword123")  // ❌ 감지되지 않음
            .build();
    }

    // ❌ 위험: API 키 하드코딩
    private static final String AWS_ACCESS_KEY = "AKIA5ZXP9...";
    private static final String SLACK_BOT_TOKEN = "xoxb-123456...";
}
```

---

## ✨ 방어 코드/설정 (After — 공격 원리를 알고 설계한 구현)

### 방어 1: SpotBugs + SpotBugs Security Plugin

```gradle
plugins {
    id 'java'
    id 'org.springframework.boot' version '3.2.0'
    
    // ✅ SpotBugs 플러그인 추가
    id 'com.github.spotbugs' version '6.0.0'
    
    // ✅ SpotBugs Security 플러그인
    id 'com.h3xstream.spotbugs' version '1.1.3'
}

dependencies {
    // SpotBugs 주석 (취약점 억제 명시)
    compileOnly 'com.google.code.findbugs:annotations:3.0.1'
    
    // Security 확장
    spotbugsPlugins 'com.h3xstream.findsecbugs:findsecbugs-plugin:1.13.0'
}

// SpotBugs 설정
spotbugs {
    effort = com.github.spotbugs.snom.Effort.MAX  // 최대 정확도
    reportLevel = com.github.spotbugs.snom.Confidence.LOW  // 모든 레벨 리포트
    
    // 제외할 버그 패턴
    excludeFilter = file('spotbugs-exclude.xml')
}

spotbugsMain {
    reports {
        html.required = true
        xml.required = true
    }
}

// ✅ CI/CD에서 검사 실패하도록
task checkSpotBugs {
    dependsOn spotbugsMain
    doLast {
        // 리포트 존재 여부 확인
        if (file('build/reports/spotbugs/main.html').exists()) {
            println "SpotBugs report: build/reports/spotbugs/main.html"
        }
    }
}

build.dependsOn checkSpotBugs
```

**spotbugs-exclude.xml** (허용 가능한 패턴 제외):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<FindBugsFilter>
    <!-- 테스트 코드는 제외 -->
    <Match>
        <Class name="~.*Test.*" />
    </Match>
    
    <!-- 특정 패턴은 의도적으로 허용 -->
    <Match>
        <Bug pattern="SE_BAD_FIELD" />
        <Class name="com.example.legacy.OldClass" />
    </Match>
</FindBugsFilter>
```

### 방어 2: SonarQube 보안 규칙

```gradle
plugins {
    id 'org.sonarqube' version '4.4.1.3373'
}

sonarqube {
    properties {
        property "sonar.projectKey", "my-app"
        property "sonar.host.url", "http://sonarqube.example.com"
        property "sonar.login", System.getenv("SONAR_TOKEN")
        
        // ✅ 보안 규칙 활성화
        property "sonar.security.hotspots.reviewed.percentage", "100"
        property "sonar.java.coverageExclusions", "**/config/**"
        
        // ✅ SQL 인젝션, XSS 탐지
        property "sonar.java.spotbugs.reporting.queries", "BUG_PATTERN"
        
        // ✅ 취약점 임계값
        property "sonar.qualitygate.gate", "SonarQube way"
        property "sonar.qualitygate.wait_for_quality_gate", "true"
    }
}

tasks.register('codeQuality') {
    dependsOn 'sonarqube'
    doLast {
        println "Quality Gate status: Check SonarQube dashboard"
    }
}
```

**SonarQube 보안 규칙 (java:S6437)**:
```yaml
# SonarQube에서 탐지하는 취약점:

S2091: Expression Language Injection (EL 인젝션)
       Pattern: String.format("SELECT * FROM users WHERE id = %s", userInput)

S3649: SQL Injection (SQL 인젝션)
       Pattern: "SELECT * FROM users WHERE username = '" + username + "'"

S5131: Cross-Site Scripting (XSS)
       Pattern: response.getWriter().println(userInput)

S4507: Exposing Exceptions (예외 노출)
       Pattern: throw new Exception(errorDetails)

S1078: Stack Trace Exposure (스택 트레이스 노출)
       Pattern: logger.error("Error", exception)  # 스택 트레이스 로깅

S5144: Command Injection (커맨드 인젝션)
       Pattern: Runtime.getRuntime().exec(userInput)

S2068: Hard-coded Credentials (하드코딩 자격증명)
       Pattern: password = "secret123"
```

### 방어 3: GitHub Actions CI/CD 파이프라인

```yaml
# .github/workflows/security.yml
name: Security Checks

on:
  pull_request:
    branches: [ main, develop ]
  push:
    branches: [ main ]

jobs:
  sast:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # 모든 이력 필요 (gitleaks용)
      
      # ✅ 1단계: Gitleaks (커밋 이력에서 비밀번호 검사)
      - name: Gitleaks (Scan for secrets)
        uses: gitleaks/gitleaks-action@v2
        with:
          source: "."
          verbose: true
      
      # ✅ 2단계: SpotBugs (버그 패턴 검사)
      - uses: actions/setup-java@v4
        with:
          java-version: '21'
          distribution: 'eclipse-temurin'
      
      - name: SpotBugs Analysis
        run: |
          ./gradlew spotbugsMain
      
      - name: Upload SpotBugs Report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: spotbugs-report
          path: build/reports/spotbugs/main.html
      
      # ✅ 3단계: SonarQube (종합 품질 검사)
      - name: SonarQube Scan
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
        run: |
          ./gradlew sonarqube \
            -Dsonar.projectKey=my-app \
            -Dsonar.host.url=https://sonarqube.example.com
      
      # ✅ 4단계: 취약점 발견 시 PR 코멘트
      - name: Comment PR on Issues
        if: failure()
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: '❌ Security checks failed. Please review SpotBugs and SonarQube reports.'
            })
      
      # ✅ 5단계: 게이트 실패 시 PR 차단
      - name: Block PR if Security Issues Found
        if: failure()
        run: |
          echo "Security issues detected. Blocking PR merge."
          exit 1
```

### 방어 4: SQL 안전 코드

```java
@Service
public class SecureUserService {

    @Autowired
    private UserRepository userRepository;

    // ✅ 방어 1: JPA Repository 사용 (자동 PreparedStatement)
    public User findUserByUsername(String username) {
        // JPA가 내부적으로 PreparedStatement 사용
        // SQL 인젝션 자동 방지
        return userRepository.findByUsername(username);
    }

    // ✅ 방어 2: PreparedStatement 명시적 사용
    public List<User> searchUsers(String searchTerm) {
        String sql = "SELECT * FROM users WHERE name ILIKE ?";  // ?로 파라미터화
        
        return jdbcTemplate.query(sql, new Object[]{searchTerm}, 
            new UserRowMapper());
        
        // SpotBugs: ✅ 합격 (PreparedStatement 패턴 감지)
    }

    // ✅ 방어 3: NamedParameterJdbcTemplate (가독성 향상)
    public List<User> findByStatus(String status) {
        String sql = "SELECT * FROM users WHERE status = :status";
        
        Map<String, Object> params = new HashMap<>();
        params.put("status", status);
        
        return namedParameterJdbcTemplate.query(sql, params, 
            new UserRowMapper());
    }

    // ✅ 방어 4: 예외 정보 은폐
    public User getUserById(Long id) {
        try {
            return userRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("User not found"));
        } catch (DataAccessException e) {
            // 내부: 로그에만 기록
            logger.error("Database error for user id: {}", id, e);
            
            // 외부: 일반 에러 메시지
            throw new ApplicationException("Failed to retrieve user");
        }
    }

    // ✅ 방어 5: XSS 방지 (입력 검증)
    public ResponseEntity<?> updateUserBio(Long userId, String bio) {
        // 1. 길이 검증
        if (bio == null || bio.length() > 500) {
            throw new ValidationException("Bio must be less than 500 characters");
        }
        
        // 2. HTML 엔티티 인코딩 (HtmlUtils 또는 OWASP)
        String encodedBio = HtmlUtils.htmlEscape(bio);
        
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new EntityNotFoundException("User not found"));
        
        user.setBio(encodedBio);
        userRepository.save(user);
        
        return ResponseEntity.ok("Bio updated successfully");
    }
}

// Repository (JPA - 자동 SQL 파라미터화)
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
    List<User> findByStatusAndEmailContaining(String status, String emailPart);
}
```

### 방어 5: Gitleaks 설정

```bash
# .gitleaks.toml
[general]
exit-code = 1  # 발견 시 exit code 1

# 보안 패턴 정의
[[rules]]
id = "password"
description = "Password hardcoded"
regex = '(?i)(password|passwd|pwd)\s*[:=]\s*["\']?([a-zA-Z0-9!@#$%^&*]+)["\']?'
tags = ["default", "PII"]

[[rules]]
id = "api_key"
description = "API Key"
regex = '(?i)(api[_-]?key|apikey)\s*[:=]\s*[a-zA-Z0-9\-_]{20,}'
tags = ["default", "secrets"]

[[rules]]
id = "aws_key"
description = "AWS Access Key"
regex = 'AKIA[0-9A-Z]{16}'
tags = ["default", "AWS"]

[[rules]]
id = "private_key"
description = "Private Key"
regex = '-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----'
tags = ["default", "secrets"]

# 제외할 경로/커밋
[whitelist]
paths = [
    'test/fixtures/',
    'docs/examples/',
    '.git/objects/'
]
commits = [
    # 이전에 발견된 비밀번호는 무시
    'a1b2c3d4e5f6g7h8i9j0'
]

# false positive 억제
[allowlist]
regexes = [
    'example_password',  # 문서 예시는 허용
    'test_api_key_12345'  # 테스트 키는 허용
]
```

**Gitleaks CI 실행**:
```bash
# 1. 설치
brew install gitleaks

# 2. 현재 저장소 스캔
gitleaks detect

# 3. pre-commit 훅으로 모든 커밋 검사
gitleaks detect --source . --verbose --redact

# 4. 특정 커밋만 검사
gitleaks detect --log-opts HEAD~5..HEAD  # 최근 5개 커밋
```

---

## 🔬 공격 원리 분석 (SAST 탐지 메커니즘)

### 버그 패턴 매칭 예시

```java
// SpotBugs가 탐지하는 패턴:

// 1. SQL 인젝션 (S3649)
String sql = "SELECT * FROM users WHERE id = " + userId;  // ❌ 탐지
// 이유: + 연산자로 문자열 결합 + SQL 키워드 포함

// 2. 예외 노출 (S1078)
logger.error("Error processing order", exception);  // ⚠️ 의심
// 이유: Exception 객체가 로그에 포함 가능

// 3. 하드코딩된 비밀번호 (S2068)
private static final String PASSWORD = "admin123";  // ❌ 탐지
// 이유: password/secret 키워드 + 문자열 리터럴

// 4. 정보 노출 (S4507)
throw new RuntimeException("User not found for ID: " + userId);  // ❌ 탐지
// 이유: Exception 생성자에 사용자 입력값 포함

// 5. XSS (S5131)
String html = "<p>" + userInput + "</p>";  // ❌ 탐지
// 이유: 사용자 입력 + HTML 문자열 결합
```

### Control Flow Graph (CFG) 분석

```
SAST 도구는 코드의 제어 흐름을 그래프로 분석:

def processPayment(amount):  // 진입점
    ↓
    user = getUser()  // null일 수 있음
    ↓
    user.deductAmount(amount)  // null dereference!
    ↓
    return success

SAST가 탐지:
"Potential Null Pointer Exception at line 4"
```

---

## 💻 실전 실험 (취약점 재현 → 공격 → 방어 검증)

### 실험 1: SpotBugs 취약점 탐지

```bash
# 1. 취약한 코드로 빌드
git checkout vulnerable-branch
./gradlew clean build spotbugsMain

# 2. 리포트 확인
open build/reports/spotbugs/main.html

# 결과:
# ❌ SQL Injection (H1: Hard coded SQL parameter)
#    File: UserService.java, Line 45
#    "SELECT * FROM users WHERE id = " + userId

# ❌ Information Exposure (IS: Inconsistent synchronization)
#    File: AuthController.java, Line 32
#    Exception object logged without masking

# 3. 안전한 버전으로 수정
git checkout secure-branch
./gradlew spotbugsMain

# 결과:
# ✅ No bugs found
```

### 실험 2: GitHub Actions 게이트 실행

```bash
# 1. PR 생성 (취약한 코드)
git checkout -b add-user-search
# 취약한 코드 추가
git push origin add-user-search

# 2. GitHub Actions 자동 실행
# → SpotBugs 검사 실행
# → PR 커멘트:
#   "❌ Security checks failed: 2 issues found
#    - SQL Injection (UserService.java:45)
#    - Exception Exposure (AuthController.java:32)"

# 3. PR 병합 불가 (Status Check Failed)
# → 개발자는 취약점 수정 후 재커밋해야 함

# 4. 수정 후 재 push
git add .
git commit -m "Fix: SQL injection and exception exposure"
git push origin add-user-search

# 5. GitHub Actions 재 실행
# → ✅ All checks passed
# → PR 병합 가능
```

### 실험 3: Gitleaks 커밋 차단

```bash
# 1. 비밀번호를 포함한 커밋 시도
echo "password: SuperSecret123" >> config.properties
git add config.properties
git commit -m "Add configuration"

# pre-commit 훅 또는 CI에서 Gitleaks 실행:
gitleaks detect

# 출력:
# ⚠️  Gitleaks scan detected 1 secret

# Matches:
# File: config.properties
# Pattern: password
# Secret: "SuperSecret123"
# Commit: abc1234

# → 커밋 차단

# 2. 수정
echo "password: ${DB_PASSWORD}" >> config.properties  # 환경변수 사용
rm -f config.properties  # 또는 .gitignore 추가
git add .gitignore
git commit -m "Move secrets to environment variables"

# → 커밋 성공
```

---

## 📊 SAST 도구 비교

| 도구 | 언어 | 검사 항목 | 정확도 | False Positive |
|------|------|---------|--------|------------|
| **SpotBugs** | Java | 버그 패턴 | 높음 | 낮음 |
| **SonarQube** | Java, C#, JS | 보안, 코드 품질 | 매우 높음 | 중간 |
| **Gitleaks** | 모든 언어 | 비밀번호/키 | 높음 | 낮음 |
| **Checkmarx** | 모든 언어 | 종합 보안 | 매우 높음 | 높음 |
| **Fortify** | 모든 언어 | 종합 보안 | 매우 높음 | 높음 |

---

## 📌 핵심 정리

1. **SAST는 필수**: 코드 리뷰 전에 자동으로 버그 패턴 탐지
2. **다층 방어**: SpotBugs(패턴) + SonarQube(종합) + Gitleaks(비밀번호)
3. **CI/CD 게이트**: PR 병합 전에 보안 검사 필수 통과
4. **조기 피드백**: 개발자가 작성 직후 바로 취약점 알림
5. **SQL 파라미터화**: JPA Repository 또는 PreparedStatement 필수
6. **예외 정보 은폐**: 내부 로그 vs 외부 응답 분리
7. **비밀번호 관리**: Gitleaks로 커밋 이력에서 자동 감지

---

## 🤔 생각해볼 문제 (+ 해설)

### Q1. SAST가 모든 취약점을 찾을 수 있는가?
**해설**: 아니요. SAST는 정적 분석이므로 런타임 취약점(타이밍 공격, 경쟁 조건)은 찾을 수 없습니다. DAST(동적 분석)와 결합해야 합니다.

### Q2. False Positive를 줄이려면?
**해설**: 도구별 제외 필터(spotbugs-exclude.xml) 설정, 테스트 코드 제외, 화이트리스트 관리 필요. 하지만 과도한 제외는 실제 취약점을 놓칠 수 있으므로 주의.

### Q3. SonarQube는 비싼가?
**해설**: 오픈소스 커뮤니티 버전(무료) 있으며, 엔터프라이즈 버전은 유료입니다. GitHub Actions와 통합 시 클라우드 버전도 가능.

<div align="center">

**[홈으로 🏠](../README.md)** | **[다음: DAST — OWASP ZAP ➡️](./02-dast-owasp-zap.md)**

</div>
