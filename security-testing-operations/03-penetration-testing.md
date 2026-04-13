# 침투 테스트 방법론

---

## 🎯 핵심 질문

- **침투 테스트의 5단계는?** Reconnaissance → Scanning → Exploitation → Post-Exploitation → Reporting
- **외부 침투 테스트와 내부 침투 테스트의 차이는?** 외부는 공격자 시각, 내부는 악의적 내부자 시각입니다.
- **Burp Suite의 Intruder와 Repeater는?** Repeater는 수동 테스트, Intruder는 자동 페이로드 주입입니다.
- **버그 바운티 보고서를 어떻게 작성하는가?** 심각도, 재현 단계, 영향 범위를 명확히 합니다.

---

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

### Yahoo! 보안 침해 (2013-2014)
**침투 테스트 부재의 결과**:
```
1. Reconnaissance 단계:
   → Yahoo!의 직원 이메일 서버 구조 파악
   
2. Scanning:
   → 과거 XSS 취약점 발견 (보고했으나 미패치)
   
3. Exploitation:
   → XSS를 통해 쿠키 탈취
   → 관리자 계정 접근
   
4. Post-Exploitation:
   → 내부 네트워크 접근
   → 3년간 사용자 데이터 유출 (5억 명)
   
5. 결과:
   → 30억 달러 인수 가격 2억 달러 인하
   → 신뢰도 완전 상실
```

---

## 😱 취약한 코드/설정 (Before — 침투 테스트 미실시)

### 취약 1: 자동 로그인 토큰 (IDOR)

```java
@RestController
public class UserController {

    // ❌ 위험: 사용자 ID를 직접 URL에 노출, 권한 확인 없음
    @GetMapping("/api/users/{userId}/profile")
    public ResponseEntity<?> getProfile(@PathVariable Long userId) {
        // 현재 로그인한 사용자가 다른 사용자의 정보를 요청해도 반환
        User user = userRepository.findById(userId).orElseThrow();
        return ResponseEntity.ok(user);
    }

    // 공격:
    // 1. 나의 프로필 조회: GET /api/users/1/profile (성공)
    // 2. 다른 사용자 프로필 조회: GET /api/users/2/profile (성공!)
    // 3. 자동 증가하는 ID로 모든 사용자 정보 추출 가능
}
```

### 취약 2: 약한 인증 (기본 자격증명)

```yaml
# ❌ 위험: 기본 사용자명/비밀번호 변경 안 함
spring:
  security:
    user:
      name: admin  # 기본값
      password: password  # 기본값 (변경되지 않음)

# 공격:
# curl -u admin:password http://localhost:8080/admin
# → 관리자 대시보드 접근
```

### 취약 3: 취약한 세션 관리

```java
@Configuration
public class SessionConfig extends WebSecurityConfigurerAdapter {

    // ❌ 위험: 세션 토큰이 예측 가능
    protected void configure(HttpSecurity http) throws Exception {
        http.sessionManagement()
            .sessionFixationProtection(SessionFixationProtectionStrategy.NONE)  // ❌
            .sessionCreationPolicy(SessionCreationPolicy.ALWAYS);  // ❌ 무조건 생성
    }
}

// 공격:
// 세션 토큰: session_1, session_2, session_3... (순차적)
// 침투 테스터가 쉽게 예측 → 다른 사용자 세션 탈취 가능
```

---

## ✨ 방어 코드/설정 (After — 침투 테스트 고려)

### 방어 1: IDOR 방지

```java
@RestController
public class SecureUserController {

    @Autowired
    private AuthenticationService authService;
    @Autowired
    private UserRepository userRepository;

    // ✅ 방어: 현재 사용자 확인 후 자신의 데이터만 반환
    @GetMapping("/api/users/{userId}/profile")
    public ResponseEntity<?> getProfile(
            @PathVariable Long userId,
            @AuthenticationPrincipal UserDetails currentUser) {
        
        // 1. 인증 확인
        if (currentUser == null) {
            return ResponseEntity.status(401).build();
        }

        // 2. 현재 사용자와 요청 대상 사용자 확인
        String currentUsername = currentUser.getUsername();
        User requestedUser = userRepository.findById(userId)
            .orElseThrow(() -> new EntityNotFoundException("User not found"));

        // 3. 권한 확인 (본인이거나 관리자만)
        if (!requestedUser.getUsername().equals(currentUsername) && 
            !currentUser.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))) {
            return ResponseEntity.status(403).build();  // Forbidden
        }

        return ResponseEntity.ok(requestedUser.getProfileDto());
    }

    // ✅ 방어: 내 정보 조회 (UUID 기반)
    @GetMapping("/api/me/profile")
    public ResponseEntity<?> getMyProfile(@AuthenticationPrincipal UserDetails currentUser) {
        User user = userRepository.findByUsername(currentUser.getUsername());
        return ResponseEntity.ok(user.getProfileDto());
    }

    // ✅ 방어: 권한 확인 어노테이션
    @GetMapping("/api/users/{userId}/sensitive")
    @PreAuthorize("@securityService.canAccessUser(#userId)")
    public ResponseEntity<?> getSensitiveData(@PathVariable Long userId) {
        return ResponseEntity.ok(userRepository.findById(userId).orElseThrow());
    }
}

@Component
public class SecurityService {
    @Autowired
    private UserRepository userRepository;

    public boolean canAccessUser(Long userId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) return false;

        User currentUser = userRepository.findByUsername(auth.getName());
        
        // 본인 확인
        if (currentUser.getId().equals(userId)) {
            return true;
        }

        // 관리자 확인
        return auth.getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
    }
}
```

### 방어 2: 강력한 인증

```yaml
# ✅ 방어: 환경변수로 자격증명 관리
spring:
  security:
    user:
      name: ${APP_ADMIN_USER:admin}
      password: ${APP_ADMIN_PASSWORD:generate-strong-password}  # 환경변수 필수

# .env 파일 (개발용, Git 제외)
APP_ADMIN_USER=admin
APP_ADMIN_PASSWORD=SuperComplexPassword123!@#$%^&*

# 프로덕션: 환경변수로 주입
# docker run -e APP_ADMIN_PASSWORD=$(openssl rand -base64 32)
```

### 방어 3: 안전한 세션 관리

```java
@Configuration
@EnableWebSecurity
public class SecureSessionConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // ✅ 세션 보안
            .sessionManagement(session -> session
                .sessionFixationProtection(SessionFixationProtectionStrategy.MIGRATE_SESSION)  // 로그인 후 세션 재생성
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)  // 필요할 때만 생성
                .maximumSessions(1)  // 동시 세션 1개만 허용
                .expiredUrl("/login?expired")  // 만료된 세션 처리
            )
            
            // ✅ 쿠키 보안
            .rememberMe(rm -> rm
                .key("secure-random-key-12345")  // 기본값 변경
                .tokenValiditySeconds(86400)  // 24시간
            )
            
            // ✅ CSRF 보호
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            );
        
        return http.build();
    }

    @Bean
    public ServletContextInitializer servletContextInitializer() {
        return servletContext -> {
            SessionCookieConfig sessionCookieConfig = servletContext.getSessionCookieConfig();
            sessionCookieConfig.setSecure(true);  // HTTPS only
            sessionCookieConfig.setHttpOnly(true);  // JavaScript 접근 불가
            sessionCookieConfig.setPath("/");
            sessionCookieConfig.setMaxAge(1800);  // 30분
        };
    }
}
```

### 방어 4: Burp Suite를 이용한 수동 테스트

```bash
# 1. Burp Suite 시작 (프록시)
# Preferences → Network → Listeners → 127.0.0.1:8081

# 2. 브라우저 프록시 설정
# HTTP: 127.0.0.1:8081

# 3. Repeater로 요청 수정 테스트
# 1. Intercept 탭에서 요청 캡처
# 2. Send to Repeater
# 3. 요청 수정:
#    - /api/users/1/profile → /api/users/2/profile (IDOR 테스트)
#    - Authorization 헤더 제거 (인증 우회 테스트)
#    - Content-Type: application/json → text/plain (타입 검증 테스트)

# 4. Intruder로 자동 공격
# 1. Send to Intruder
# 2. Target 탭 확인
# 3. Positions 탭: 공격 지점 선택 (userId)
# 4. Payloads 탭: 페이로드 설정 (1-1000)
# 5. Attack 시작
# → 응답 길이, 상태 코드 다른 것 발견 가능
```

### 방어 5: 침투 테스트 체크리스트

```markdown
# Spring Boot 애플리케이션 침투 테스트 체크리스트

## Authentication (인증)
- [ ] 기본 자격증명 변경 여부 확인
- [ ] 비밀번호 정책 (최소 길이, 복잡도) 확인
- [ ] 계정 잠금 기능 (5회 실패 후) 확인
- [ ] 비밀번호 재설정 토큰 만료 여부 확인
- [ ] 2FA/MFA 적용 여부 확인
- [ ] OAuth2/OIDC 설정 검증

## Session Management (세션)
- [ ] 세션 고정 공격 방지 여부
- [ ] 동시 세션 제한 확인
- [ ] 세션 타임아웃 설정 (30분 이내)
- [ ] 쿠키 보안 플래그 (Secure, HttpOnly, SameSite)
- [ ] 로그아웃 후 세션 완전 제거 여부

## Authorization (권한)
- [ ] IDOR 취약점 (사용자별 리소스 접근)
- [ ] 수직 권한 상승 (일반 사용자 → 관리자)
- [ ] 수평 권한 상승 (사용자1 → 사용자2 데이터)
- [ ] 기능별 권한 확인
- [ ] API 엔드포인트별 권한 확인

## Input Validation (입력)
- [ ] SQL Injection 테스트
- [ ] XSS (Stored, Reflected) 테스트
- [ ] Path Traversal 테스트
- [ ] Command Injection 테스트
- [ ] XXE (XML External Entity) 테스트
- [ ] LDAP Injection 테스트
- [ ] 파일 업로드 검증 (타입, 크기, 콘텐츠)

## Business Logic (비즈니스 로직)
- [ ] 가격 조작 (클라이언트에서 금액 수정)
- [ ] 주문 우회 (결제 단계 스킵)
- [ ] 재고 조작 (음수 주문)
- [ ] 할인 남용 (중복 적용)
- [ ] 레이스 컨디션 (동시 요청)

## API Security
- [ ] Rate Limiting 확인
- [ ] API 버전 관리 (/v1, /v2)
- [ ] API 토큰 만료 확인
- [ ] CORS 정책 검증
- [ ] API 문서 노출 여부 (Swagger)

## Infrastructure
- [ ] HTTP/HTTPS 사용 여부
- [ ] 보안 헤더 (CSP, X-Frame-Options 등)
- [ ] HSTS 활성화 여부
- [ ] Actuator 엔드포인트 노출 여부
- [ ] 에러 페이지 정보 노출
- [ ] 백업 파일 (.bak, .old) 접근 가능 여부

## Data Protection
- [ ] 민감 데이터 로깅 여부
- [ ] 암호화 알고리즘 (AES-256, SHA-256 이상)
- [ ] 키 관리 (하드코딩 여부)
- [ ] 데이터 마스킹 (응답, 로그)

## Compliance
- [ ] GDPR 준수 (개인정보 삭제)
- [ ] PCI DSS (신용카드 정보 보호)
- [ ] 감사 로그 기록 (who, when, what)
```

---

## 🔬 공격 원리 분석 (침투 테스트 공격 방식)

### IDOR 공격 예시

```
1단계: 재현 (Reproduction)
   GET /api/users/123/profile
   → {"id": 123, "name": "Alice", "email": "alice@example.com"}

2단계: IDOR 확인
   GET /api/users/124/profile (다른 사용자)
   → {"id": 124, "name": "Bob", "email": "bob@example.com"}
   (접근 불가해야 하는데 접근 가능!)

3단계: 자동화
   for i in {1..10000}:
       GET /api/users/$i/profile
       → 모든 사용자 정보 추출 가능
```

### 세션 고정 공격

```
1. 공격자: 정상 로그인
   POST /login → Set-Cookie: JSESSIONID=abc123
   → 이 세션 ID 기억

2. 공격자: 희생자에게 링크 전송
   http://target.com/?JSESSIONID=abc123

3. 희생자: 링크 클릭 후 로그인
   → 공격자의 세션 ID(abc123) 그대로 사용
   
4. 공격자: 희생자의 세션으로 접근
   JSESSIONID=abc123으로 요청
   → 희생자 계정으로 인증됨!
```

---

## 💻 실전 실험 (침투 테스트 실습)

### 실험 1: IDOR 취약점 발견

```bash
# 1. 로그인
curl -c cookies.txt -X POST http://localhost:8080/login \
  -d "username=alice&password=password"

# 2. 내 정보 조회
curl -b cookies.txt http://localhost:8080/api/users/1/profile
# {"id": 1, "name": "Alice", "email": "alice@example.com"}

# 3. 다른 사용자 정보 조회 (IDOR!)
curl -b cookies.txt http://localhost:8080/api/users/2/profile
# {"id": 2, "name": "Bob", "email": "bob@example.com"}
# → 접근 불가해야 하는데 접근 가능!

# 4. 수정까지 가능하면 더 심각
curl -b cookies.txt -X PUT http://localhost:8080/api/users/2/profile \
  -H "Content-Type: application/json" \
  -d '{"name": "Hacked"}'
# → 다른 사용자의 정보 변조!
```

### 실험 2: Burp Suite Intruder로 자동 공격

```
1. Burp Suite 시작
2. 취약한 앱 접근: http://localhost:8080/api/users/1/profile
3. Intercept → Send to Intruder
4. Positions: /api/users/1/profile에서 "1" 선택
5. Payloads: 1, 2, 3, ..., 100
6. Attack 클릭
7. Results에서 응답 길이 다른 것 확인
   - 1: 150 bytes (자신의 정보)
   - 2: 160 bytes (다른 사용자 - IDOR!)
   - 3: 155 bytes
   ...
```

---

## 📌 핵심 정리

1. **침투 테스트는 공격자 관점**: 방어가 실제로 작동하는지 확인
2. **5단계 방법론**: Reconnaissance → Scanning → Exploitation → Post-Exploitation → Reporting
3. **IDOR 방지**: 사용자별 권한 확인 필수
4. **세션 고정 방지**: 로그인 후 세션 ID 재생성
5. **Burp Suite**: 수동 테스트 & 자동 스캔 도구
6. **버그 바운티**: 발견한 취약점을 명확히 문서화하고 보고

---

## 🤔 생각해볼 문제 (+ 해설)

### Q1. IDOR와 권한 제어 (Authorization)의 차이는?
**해설**: 
- IDOR: 권한 제어는 있지만, 객체 ID를 예측/조작하면 우회 가능
- 권한 제어 부재: 권한 확인 자체가 없음

예: `/api/users/1/profile` 조회 시, 본인인지 확인하지 않으면 IDOR

### Q2. 침투 테스트는 얼마나 자주 해야 하는가?
**해설**: 
- 초기 개발 완료 후: 1회
- 주요 기능 추가 후: 1회
- 정기적으로: 연 2회 이상
- 보안 사고 후: 즉시

### Q3. 버그 바운티 플랫폼에서 중복 신고는?
**해설**: 같은 취약점을 다른 사람이 이미 신고했다면 일반적으로 상금이 없습니다. 먼저 신고한 사람이 우선입니다.

<div align="center">

**[⬅️ 이전: DAST — OWASP ZAP](./02-dast-owasp-zap.md)** | **[홈으로 🏠](../README.md)** | **[다음: 보안 로깅과 모니터링 ➡️](./04-security-logging-monitoring.md)**

</div>
