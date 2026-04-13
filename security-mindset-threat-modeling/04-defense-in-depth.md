# Defense in Depth — 계층별 방어 설계

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- "Defense in Depth"가 단순한 보안 레이어 쌓기와 어떻게 다른가?
- 단일 방어선(WAF만, Spring Security만)이 왜 충분하지 않은가?
- 네트워크/애플리케이션/데이터 레이어에서 각각 무엇을 방어해야 하는가?
- "Security by Default"는 무엇이고, Spring에서 어떻게 구현하는가?
- 각 레이어의 방어가 실패했을 때 다음 레이어가 어떻게 피해를 제한하는가?

---

## 🔍 왜 Defense in Depth가 실무에서 중요한가

2021년 Twitch 소스코드 유출 사고를 분석한 결과, 공격자는 단 하나의 잘못 설정된 서버 설정을 통해 내부 네트워크로 진입했다. 이후 내부 네트워크에서 서비스 간 인증이 없었고, DB 접근 권한이 과도하여 전체 소스코드와 수익 데이터를 수집할 수 있었다.

이 사고에서 각 레이어에 방어가 있었다면:
- **네트워크 레이어**: 잘못된 서버 설정이 내부 네트워크로의 진입을 막았을 것
- **서비스 레이어**: 서비스 간 인증이 있었다면 내부 이동(Lateral Movement)이 제한됐을 것
- **데이터 레이어**: 최소 권한 계정이었다면 접근 가능한 데이터가 제한됐을 것

**Defense in Depth는 어떤 한 레이어가 뚫렸을 때 다음 레이어가 피해를 제한하는 구조다.**

---

## 😱 흔한 실수 (Before — 단일 방어선에 의존)

```
전형적인 실수 1: WAF만 믿는 경우
  "WAF(Web Application Firewall)를 설치했으니 SQL Injection은 막혔다"
  
  현실:
    WAF는 알려진 패턴을 차단
    변형된 페이로드, 인코딩, 분산 공격으로 우회 가능
    WAF가 뚫린 이후 애플리케이션에 2차 방어 없음

전형적인 실수 2: Spring Security만 믿는 경우
  "Spring Security 설정했으니 인증/인가는 해결됐다"
  
  현실:
    Spring Security는 HTTP 레이어 인증을 처리
    서비스 간 내부 API 호출은 무방비
    DB 계정 권한, 로그 부재, 네트워크 격리 없음

전형적인 실수 3: DB 암호화만 믿는 경우
  "DB 자체 암호화(TDE)를 켰으니 데이터가 안전하다"
  
  현실:
    TDE는 디스크 도난에 대한 방어
    애플리케이션이 DB에 접속하여 읽는 데이터는 평문
    SQL Injection으로 데이터를 읽을 때 TDE는 무력함
```

---

## ✨ 올바른 접근 (After — 계층별 방어 설계)

```
같은 위협(SQL Injection)에 대한 계층별 방어:

레이어 1: 네트워크
  DB가 인터넷에 직접 노출되지 않도록 VPC 내부에 배치
  → 공격자가 외부에서 직접 DB에 접근 불가

레이어 2: 애플리케이션 (Spring)
  PreparedStatement / 파라미터 바인딩으로 SQL Injection 차단
  → 정상적인 경로에서 공격 차단

레이어 3: DB 계정 권한 (최소 권한)
  Order Service DB 계정: orders 테이블에만 SELECT/INSERT 권한
  → 공격 성공해도 접근 가능한 데이터 최소화

레이어 4: 감사 로그
  비정상적인 쿼리 패턴(대량 SELECT, UNION 사용)을 DB 감사 로그로 탐지
  → 뚫리더라도 즉시 탐지하여 피해 제한

레이어 5: 데이터 암호화
  카드번호, 주민번호는 애플리케이션 레벨에서 암호화 후 저장
  → 데이터를 읽어도 복호화 키 없이는 무용지물
```

---

## 🔬 레이어별 방어 설계 — Spring 서비스 기준

### Layer 1: 네트워크 레이어

```
목표: 공격 표면을 최소화하고 내부 서비스를 외부에서 격리

방어 수단:
  VPC (Virtual Private Cloud)
    - DB, Redis, 내부 서비스를 프라이빗 서브넷에 배치
    - 인터넷에서 직접 접근 불가능
    - NAT Gateway를 통해서만 외부 통신

  보안 그룹 (Security Group)
    - Order Service → MySQL: 3306 포트만 허용
    - 외부 → Spring Service: 443 포트만 허용
    - 인스턴스 간 불필요한 포트 차단

  네트워크 ACL
    - IP 기반 블랙리스트
    - 알려진 악성 IP 차단

  WAF
    - OWASP 규칙셋 적용 (SQL Injection, XSS 패턴)
    - Rate Limiting (레이어 7 수준)
    - Bot 탐지

방어 실패 시 다음 레이어 역할:
  네트워크 레이어가 뚫려도 애플리케이션 레이어에서 재차 방어
```

---

### Layer 2: 호스트/컨테이너 레이어

```
목표: 서비스가 실행되는 환경 자체를 강화

방어 수단:
  최소화된 컨테이너 이미지
    # 취약한 방식
    FROM ubuntu:latest       # 불필요한 도구 포함
    
    # 안전한 방식
    FROM gcr.io/distroless/java17-debian12  # 최소 런타임만 포함
    USER nonroot                             # 루트 권한 없이 실행

  읽기 전용 파일시스템
    securityContext:
      readOnlyRootFilesystem: true  # 컨테이너 내 파일 변조 불가

  권한 제한
    securityContext:
      runAsNonRoot: true
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]             # 모든 Linux 권한 제거

  비밀정보 분리
    # 취약한 방식
    ENV DB_PASSWORD=mypassword   # Dockerfile에 평문

    # 안전한 방식
    # Kubernetes Secret 또는 AWS Secrets Manager에서 런타임 주입

방어 실패 시 다음 레이어 역할:
  컨테이너가 탈취되어도 루트 권한 없이는 다른 컨테이너나 호스트 침투 어려움
```

---

### Layer 3: 애플리케이션 레이어 (Spring)

```
목표: 모든 요청을 신뢰하지 않고 검증

Spring Security 기본 설정이 켜주는 방어:
  - CSRF 보호 (기본 활성화)
  - Clickjacking 방어 (X-Frame-Options: DENY)
  - XSS 헤더 (X-XSS-Protection)
  - HTTPS 강제 (HSTS)
  - 세션 고정 공격 방어 (changeSessionId)

개발자가 직접 구현해야 하는 방어:
  // 인증 — Spring Security가 처리
  // 인가 — 개발자 책임
  @GetMapping("/api/orders/{orderId}")
  @PreAuthorize("isAuthenticated()")
  public Order getOrder(@PathVariable Long orderId,
                        @AuthenticationPrincipal UserDetails user) {
      Order order = orderRepository.findById(orderId)
          .orElseThrow(() -> new NotFoundException());
      
      // Spring Security는 이것을 해주지 않는다
      if (!order.getUserId().equals(user.getUserId())) {
          throw new ForbiddenException();  // 소유권 검증 = 개발자 책임
      }
      return order;
  }

  // 입력값 검증
  @PostMapping("/api/orders")
  public Order createOrder(@Valid @RequestBody OrderRequest request) {
      // @Valid로 Bean Validation 적용
      // 비즈니스 검증은 서비스 레이어에서 별도 수행
  }
  
  // 에러 응답 — 내부 정보 최소화
  @ExceptionHandler(Exception.class)
  public ResponseEntity<ErrorResponse> handleException(Exception e) {
      log.error("Unexpected error", e);  // 서버에는 전체 스택 로깅
      return ResponseEntity.status(500)
          .body(new ErrorResponse("Internal server error"));  // 클라이언트에는 최소 정보
  }

방어 실패 시 다음 레이어 역할:
  애플리케이션 레이어가 뚫려도 DB 계정 권한으로 피해 범위 제한
```

---

### Layer 4: 데이터 레이어

```
목표: 데이터에 도달하더라도 피해를 최소화

DB 계정 최소 권한:
  -- 서비스별 전용 계정
  CREATE USER 'order-service'@'10.0.1.%' IDENTIFIED BY '...';
  GRANT SELECT, INSERT, UPDATE ON order_db.orders TO 'order-service'@'10.0.1.%';
  -- DELETE 권한 없음, 다른 테이블 접근 불가

  -- 읽기 전용 계정 (조회 API용)
  CREATE USER 'order-reader'@'10.0.1.%' IDENTIFIED BY '...';
  GRANT SELECT ON order_db.orders TO 'order-reader'@'10.0.1.%';

  -- 배치 서비스 계정
  CREATE USER 'batch-service'@'10.0.2.%' IDENTIFIED BY '...';
  GRANT SELECT ON order_db.* TO 'batch-service'@'10.0.2.%';

애플리케이션 레벨 암호화:
  @Entity
  public class User {
      @Column
      @Convert(converter = EncryptedStringConverter.class)
      private String phoneNumber;  // 저장/조회 시 자동 암호화/복호화

      @Column
      private String password;     // BCrypt 해시로 저장 (복호화 불필요)
  }

  // 결과: DB가 탈취되어도 복호화 키 없이는 평문 데이터 접근 불가

DB 감사 로그:
  SET GLOBAL general_log = 'ON';  -- MySQL 쿼리 로깅
  -- 비정상 패턴(UNION, 대량 SELECT) 모니터링

방어 실패 시 다음 레이어 역할:
  데이터를 읽어도 암호화로 인해 원본 데이터 사용 불가
```

---

### Layer 5: 감사 및 모니터링 레이어

```
목표: 방어가 실패했을 때 즉시 탐지하고 피해 최소화

Spring AOP로 보안 이벤트 로깅:
  @Aspect
  @Component
  public class SecurityAuditAspect {
      
      @AfterThrowing(pointcut = "execution(* com.example..*(..)) && " +
                               "@annotation(preAuthorize)", 
                     throwing = "ex")
      public void logAuthorizationFailure(JoinPoint jp, 
                                          PreAuthorize preAuthorize,
                                          AccessDeniedException ex) {
          SecurityContext ctx = SecurityContextHolder.getContext();
          String userId = ctx.getAuthentication().getName();
          String method = jp.getSignature().toShortString();
          
          log.warn("AUTHORIZATION_FAILURE userId={} method={} ip={}",
                   userId, method, getClientIp());
          
          // SIEM으로 전송 또는 알림 트리거
      }
  }

이상 탐지 규칙 예시:
  - 5분 내 동일 IP에서 100회 이상 인증 실패
  - 1분 내 동일 사용자가 1000개 이상 리소스 조회
  - 비업무 시간에 관리자 API 접근
  - 새로운 국가 IP에서 관리자 로그인

방어 실패 시 다음 레이어 역할:
  공격을 막지 못해도 즉시 탐지하여 피해 제한 가능
  (평균 197일 → 수 분으로 탐지 시간 단축 목표)
```

---

## 📊 Security by Default — Spring에서의 구현

"Security by Default"는 설정하지 않아도 기본적으로 안전한 상태에서 시작하는 원칙이다.

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // 기본: 모든 요청 인증 필요 (명시적으로 예외를 열어야 함)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**").permitAll()   // 명시적 예외
                .requestMatchers("/actuator/health").permitAll()
                .anyRequest().authenticated()                  // 기본 차단
            )
            
            // 세션 고정 공격 방어 (기본 활성화)
            .sessionManagement(session -> session
                .sessionFixation().changeSessionId()
            )
            
            // 보안 헤더 (기본 활성화)
            .headers(headers -> headers
                .frameOptions().deny()                    // Clickjacking
                .xssProtection().block(true)              // XSS
                .contentSecurityPolicy("default-src 'self'")
                .httpStrictTransportSecurity()            // HSTS
            )
            
            // HTTPS 강제
            .requiresChannel(channel -> channel
                .anyRequest().requiresSecure()
            );
        
        return http.build();
    }
}
```

```
Security by Default 원칙:
  1. 기본적으로 모든 것을 차단하고, 필요한 것만 열어라
     (Allowlist > Blocklist)
  
  2. 기본 설정이 프로덕션에서도 안전해야 한다
     (개발 편의 설정을 프로덕션에서 끄는 것보다
      기본이 안전하고 개발 시 예외를 추가하는 방향)
  
  3. 보안 기능을 끄려면 명시적인 이유가 있어야 한다
     .csrf().disable()  // 이것을 작성할 때 왜 안전한지 설명할 수 있는가?
```

---

## ⚖️ 트레이드오프

| 레이어 | 보안 효과 | 도입 비용 | 운영 복잡도 |
|--------|----------|-----------|------------|
| 네트워크 격리 | 높음 | 인프라 설계 시간 | 낮음 |
| 최소 권한 계정 | 중간 | 계정 관리 시간 | 낮음 |
| 애플리케이션 방어 | 높음 | 개발 시간 추가 | 중간 |
| 데이터 암호화 | 높음 | 개발+운영 시간 | 높음 (키 관리) |
| 감사 로깅 | 탐지에 높음 | 개발 시간 추가 | 중간 (로그 저장소) |

**모든 레이어를 동시에 완벽하게 구현하는 것은 불가능하다.** 위험도가 높은 데이터와 기능부터 레이어를 쌓아 나가는 것이 현실적이다.

---

## 📌 핵심 정리

- **단일 방어선은 반드시 뚫린다** — WAF도, Spring Security도, DB 암호화도 각각 단독으로는 충분하지 않다
- **레이어마다 다른 위협을 방어** — 같은 공격에 대해 여러 레이어가 각각 다른 방식으로 방어한다
- **방어 실패 시 피해 제한이 목표** — 완벽한 방어는 불가능하므로, 뚫렸을 때 피해를 최소화하는 구조가 필요하다
- **Security by Default** — 기본이 안전하고, 예외를 명시적으로 추가하는 방향으로 설계한다
- **최소 권한 계정** — 각 서비스/기능에 필요한 최소한의 권한만 부여한다

---

## 🤔 생각해볼 문제

**문제 1**: 다음 사고 시나리오에서 각 레이어의 방어가 있었다면 피해를 어떻게 제한할 수 있었는지 분석하라.

```
사고: SQL Injection으로 order 테이블의 모든 결제 정보 유출
현재 상태:
  - WAF 있음 (SQL Injection 패턴 차단)
  - Spring + JPA 사용
  - DB 계정: root (모든 테이블 접근 가능)
  - 결제 정보: 평문 저장
  - 로깅: 없음
```

**해설**:
```
공격 흐름:
  WAF 우회 (인코딩된 페이로드) → JPA JPQL 문자열 연결 취약점 악용
  → root 계정으로 전체 DB 접근 → 결제 정보 평문 추출 → 유출

각 레이어 방어가 있었다면:
  레이어 2 (JPQL 파라미터 바인딩):
    → SQL Injection 자체가 차단되어 사고 없음

  레이어 3 (DB 최소 권한):
    → SQL Injection 성공해도 orders 테이블 SELECT만 가능
    → 다른 테이블(payments, users) 접근 불가

  레이어 4 (결제 정보 암호화):
    → orders 테이블 데이터를 읽어도 복호화 불가
    → 유출된 데이터 사용 불가

  레이어 5 (감사 로그):
    → 비정상 쿼리 패턴 탐지 → 즉시 대응
    → 유출 범위를 수개월→수 시간으로 축소
```

**문제 2**: 스타트업에서 개발자 5명이 빠르게 서비스를 런치해야 할 때, Defense in Depth 관점에서 "반드시 먼저 해야 하는 것"과 "나중에 해도 되는 것"을 우선순위로 나눠라.

**해설**:
```
반드시 먼저 (Day 1):
  ✓ DB를 인터넷에 직접 노출하지 않음 (VPC)
  ✓ 파라미터 바인딩으로 SQL Injection 방어 (코드 작성 습관)
  ✓ PasswordEncoder = BCrypt
  ✓ HTTPS 강제
  ✓ Spring Security 기본 설정 유지 (CSRF, 보안 헤더)
  비용: 거의 없음, 습관의 문제

단기 내 (첫 1개월):
  ✓ DB 계정 분리 (서비스별 최소 권한)
  ✓ Actuator 프로덕션 노출 제거
  ✓ 인증 실패 로그
  비용: 낮음, 설정 수준

성장 후 (사용자 증가 시):
  ✓ WAF 도입
  ✓ 민감 데이터 암호화
  ✓ 감사 로그 + SIEM
  ✓ 취약점 스캔 파이프라인
  비용: 중간, 전문 지식 필요
```

---

<div align="center">

**[⬅️ 이전: OWASP Top 10 2023 개요](./03-owasp-top10-overview.md)** | **[홈으로 🏠](../README.md)** | **[다음: 보안 개발 생명주기(SDL) ➡️](./05-security-development-lifecycle.md)**

</div>
