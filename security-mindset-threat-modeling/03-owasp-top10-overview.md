# OWASP Top 10 2023 개요 — 비즈니스 영향 분석

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- OWASP Top 10 2023의 10가지 취약점은 무엇이고, 실제 발생 빈도는 어떻게 되는가?
- 각 취약점이 비즈니스에 어떤 실질적 피해를 주는가?
- 취약점들이 연쇄적으로 연결되는 공격 경로는 어떻게 형성되는가?
- Spring 백엔드 개발자가 각 항목에서 가장 먼저 점검해야 할 것은 무엇인가?

---

## 🔍 왜 OWASP Top 10이 중요한가

OWASP(Open Web Application Security Project) Top 10은 수천 개의 조직이 참여한 실제 취약점 데이터를 기반으로 4년마다 갱신된다. 단순한 권고 목록이 아니라 **전 세계에서 실제로 가장 많이 악용된 취약점의 순위**다.

2023년 기준 데이터 포인트:
- 분석 대상: 500,000개 이상의 애플리케이션
- 발견된 취약점 인스턴스: 수백만 건
- 기여 조직: 글로벌 보안 기업, 정부 기관, 개인 연구자

이 문서에서는 각 항목을 "표면적 대책"이 아닌 **"왜 이 취약점이 발생하는가"**와 **"Spring 개발자가 가장 먼저 봐야 할 것"** 관점으로 정리한다.

---

## 😱 흔한 실수 — OWASP를 체크리스트로만 보는 것

```
잘못된 접근:
  "OWASP Top 10 항목을 체크리스트로 만들어서 다 체크하면 된다"
  
문제:
  A01 - 접근 제어 취약점 → "RBAC 구현함 ✓" → 체크
  실제: RBAC는 구현했지만 IDOR (개별 리소스 소유권 검증) 누락

  A03 - 인젝션 → "JPA 사용함 ✓" → 체크
  실제: JPA JPQL에 문자열 연결 사용, Native Query에 인젝션 취약점

체크리스트 통과 = 안전이 아니다
각 항목이 "왜" 발생하는지 이해해야 실제로 방어할 수 있다
```

---

## 🔬 OWASP Top 10 2023 — 항목별 심층 분석

### A01: Broken Access Control (접근 제어 취약점)

**2017년 5위 → 2021년 1위 → 2023년 1위** (가장 많이 발견되는 취약점)

```
왜 발생하는가:
  인증(Authentication)은 "누구인가?"를 확인한다
  인가(Authorization)는 "무엇을 할 수 있는가?"를 확인한다
  
  대부분의 팀은 인증에 집중하고 인가의 세부 구현을 놓친다

실제 형태:
  - IDOR: GET /api/orders/99999 → 다른 사람 주문 조회
  - 수직 권한 상승: 일반 사용자가 PUT /api/admin/users 호출
  - 경로 조작: /../../../etc/passwd
  - 메타데이터 조작: JWT claims 변조, 쿠키 변조

비즈니스 영향:
  전체 사용자 데이터 유출 → 규제 처벌(GDPR 최대 전체 매출 4%)
  경쟁사에 비즈니스 데이터 노출
  사용자 신뢰 손실 → 이탈

Spring 개발자 1순위 점검:
  모든 @GetMapping, @PostMapping에 소유권 검증이 있는가?
  PathVariable ID가 현재 인증된 사용자의 것인지 확인하는가?
```

---

### A02: Cryptographic Failures (암호화 실패)

**2017년 3위 → 2021년 2위 → 2023년 2위**

```
왜 발생하는가:
  "암호화를 쓴다"와 "올바르게 쓴다"는 다르다
  AES를 쓰더라도 ECB 모드 사용, IV 재사용, 키 하드코딩으로 무력화됨
  
실제 형태:
  - 민감 데이터(카드번호, 주민번호)를 평문으로 DB에 저장
  - MD5/SHA-1로 비밀번호 해싱 (Rainbow Table 취약)
  - HTTP로 민감 데이터 전송 (TLS 미적용)
  - 암호화 키를 application.properties에 평문으로 저장
  - AES-ECB 모드 사용 (같은 평문 → 같은 암호문 → 패턴 노출)

비즈니스 영향:
  카드 정보 유출 → PCI DSS 위반 → 카드사 계약 종료
  개인정보 유출 → 개인정보보호법 과징금
  신뢰 손실

Spring 개발자 1순위 점검:
  @Column으로 저장되는 민감 필드에 암호화 적용 여부
  PasswordEncoder가 Bcrypt/Argon2인지 (NoOpPasswordEncoder, MD5 금지)
```

---

### A03: Injection (인젝션)

**2017년 1위 → 2021년 3위 → 2023년 3위**

```
왜 발생하는가:
  사용자 입력값이 명령어/쿼리의 구조로 해석될 때 발생
  "데이터"와 "코드"의 경계가 무너지는 것

실제 형태:
  - SQL Injection: String 연결 쿼리
  - JPQL Injection: @Query("... WHERE name = '" + name + "'")
  - Command Injection: Runtime.exec(userInput)
  - XXE: XML 파서가 외부 엔터티를 처리
  - LDAP Injection: LDAP 필터에 사용자 입력 삽입

비즈니스 영향:
  전체 DB 탈취 (가장 직접적인 데이터 유출 경로)
  데이터 삭제/변조
  OS 명령 실행 → 서버 완전 탈취

Spring 개발자 1순위 점검:
  @Query 어노테이션에 문자열 연결(+)이 있는가?
  Native Query 사용 시 파라미터 바인딩(?) 사용 여부
```

---

### A04: Insecure Design (안전하지 않은 설계)

**2021년 신규 진입 → 2023년 4위**

```
왜 발생하는가:
  코드 레벨의 버그가 아닌 아키텍처/비즈니스 로직 수준의 결함
  구현을 아무리 잘해도 설계가 잘못되면 안전할 수 없다

실제 형태:
  - 비밀번호 재설정 링크를 이메일로 보내지만 만료 시간이 없음
  - 주문 취소 요청 시 결제 취소를 서버가 아닌 클라이언트가 결정
  - 관리자 기능에 2FA 없음
  - 대량 데이터 조회에 페이지네이션과 최대 한도 없음
  - 사용자가 지정한 콜백 URL을 서버가 검증 없이 호출 (SSRF 설계)

비즈니스 영향:
  패치로 수정 불가, 아키텍처 전체 재설계 필요
  재설계 비용이 초기 설계 비용의 10~100배

Spring 개발자 1순위 점검:
  비즈니스 로직에서 중요한 결정(가격, 권한, 상태 전환)이
  서버에서 이루어지는가, 클라이언트 입력을 신뢰하는가?
```

---

### A05: Security Misconfiguration (보안 설정 오류)

**2017년 6위 → 2021년 5위 → 2023년 5위**

```
왜 발생하는가:
  기본 설정이 편의성을 위해 보안을 희생하도록 설계됨
  개발/운영 환경의 설정 차이

실제 형태:
  - Spring Actuator /actuator/env, /actuator/heapdump 프로덕션 노출
  - H2 Console 프로덕션 활성화
  - CORS allowedOrigins("*") + allowCredentials(true) 조합
  - 서버 버전 정보 포함 헤더 (Server: Apache/2.4.1)
  - 불필요한 HTTP 메서드 허용 (TRACE, OPTIONS)
  - 기본 비밀번호 사용 (admin/admin)

비즈니스 영향:
  자격증명 유출로 전체 시스템 접근 가능
  내부 구조 노출로 표적 공격 용이

Spring 개발자 1순위 점검:
  application-prod.properties에서 actuator 노출 범위
  management.endpoints.web.exposure.include 설정
```

---

### A06: Vulnerable and Outdated Components (취약하고 오래된 컴포넌트)

**2017년 9위 → 2021년 6위 → 2023년 6위**

```
왜 발생하는가:
  의존성 업데이트의 회귀(Regression) 위험으로 미루게 됨
  사용 중인 라이브러리의 CVE를 모니터링하지 않음

실제 사례:
  - Spring4Shell (CVE-2022-22965): Spring Framework RCE
  - Log4Shell (CVE-2021-44228): Log4j2 JNDI RCE
  - Jackson Databind: 다수의 역직렬화 취약점

비즈니스 영향:
  원격 코드 실행(RCE) → 서버 완전 탈취
  특별한 공격 기술 없이도 공개된 익스플로잇으로 피해 가능

Spring 개발자 1순위 점검:
  ./gradlew dependencyCheckAnalyze 또는 mvn verify 로
  CVE HIGH/CRITICAL 의존성 존재 여부 확인
```

---

### A07: Identification and Authentication Failures (인증 실패)

**2017년 2위 → 2021년 7위 → 2023년 7위** (Spring Security 보급으로 하락)

```
왜 발생하는가:
  Spring Security가 기본 인증을 제공하지만
  세부 설정(알고리즘, 만료, 검증)을 잘못 구성하면 취약

실제 형태:
  - JWT alg:none 허용
  - 약한 JWT 비밀키 (secret, password123)
  - 토큰 만료 검증 누락
  - 세션 고정 공격 방어 없음
  - 브루트포스 보호 없는 로그인

Spring 개발자 1순위 점검:
  JwtDecoder 설정에서 알고리즘 명시 여부
  PasswordEncoder가 BCryptPasswordEncoder인지
```

---

### A08: Software and Data Integrity Failures (소프트웨어/데이터 무결성 실패)

**2021년 신규 → 2023년 8위** (공급망 공격 증가 반영)

```
왜 발생하는가:
  CI/CD 파이프라인, 소프트웨어 업데이트, 의존성에 대한
  무결성 검증 없이 신뢰하는 것

실제 형태:
  - 서명되지 않은 JAR 파일을 신뢰
  - 검증 없는 역직렬화 (Java ObjectInputStream)
  - 변조된 npm/Maven 패키지 (공급망 공격)
  - CI 파이프라인에 악성 스크립트 삽입

대표 사례:
  SolarWinds 공격: 소프트웨어 빌드 파이프라인 침투
  Log4Shell: 신뢰된 라이브러리의 취약점

Spring 개발자 1순위 점검:
  Java 역직렬화(ObjectInputStream) 사용 여부
  의존성 출처 검증 (Maven Central 서명 확인)
```

---

### A09: Security Logging and Monitoring Failures (로깅/모니터링 실패)

**2017년 10위 → 2021년 9위 → 2023년 9위**

```
왜 발생하는가:
  공격 자체를 막지 못했을 때 탐지하고 대응하는 것이 2차 방어선
  로깅/모니터링 부재 → 침해 사실을 수개월 후에 발견

실제 형태:
  - 로그인 실패 기록 없음 → 브루트포스 탐지 불가
  - 권한 오류 로그 없음 → IDOR 시도 탐지 불가
  - 로그가 변조 가능한 로컬 파일에만 저장
  - 이상 패턴 알림 없음 (짧은 시간에 수천 건 API 호출)

비즈니스 영향:
  평균 침해 탐지 시간: 197일 (IBM 2022 보고서)
  탐지가 늦을수록 피해 범위 확대

Spring 개발자 1순위 점검:
  인증 실패, 권한 오류, 민감 데이터 접근에 대한 로그 기록 여부
```

---

### A10: Server-Side Request Forgery (SSRF)

**2021년 신규 진입 → 2023년 10위** (클라우드 환경 증가로 중요성 상승)

```
왜 발생하는가:
  서버가 외부의 URL을 가져오는 기능(이미지 다운로드, 웹훅, URL 미리보기)에서
  공격자가 내부 URL을 지정할 수 있을 때 발생

실제 형태:
  POST /api/fetch { "url": "http://169.254.169.254/latest/meta-data/" }
  → AWS EC2 메타데이터 서비스에서 IAM 자격증명 탈취
  → S3/RDS/EC2 전체 접근 가능

비즈니스 영향:
  클라우드 자격증명 탈취 → 전체 인프라 접근
  내부 서비스 공격 (DB, Redis, 관리 API)

Spring 개발자 1순위 점검:
  RestTemplate/WebClient로 외부 URL을 요청할 때
  해당 URL이 사용자 입력에서 온 것인지
  화이트리스트 검증 존재 여부
```

---

## 📊 취약점 연쇄 공격 — SSRF → 내부망 SQL Injection

OWASP Top 10의 취약점들은 독립적으로 발생하지 않는다. 하나의 취약점이 다른 취약점을 활용하는 연쇄 공격(Attack Chain)이 실제 침해 사고에서 자주 나타난다.

```
공격 시나리오: SSRF → 내부 서비스 → SQL Injection

Step 1: SSRF (A10)
  공격자가 이미지 URL 입력:
  POST /api/images/preview
  { "url": "http://internal-admin-service:8080/api/users" }
  → 서버가 내부 관리 서비스에 요청 전송
  → 외부에서 접근 불가한 내부 API 응답 수신

Step 2: 내부 서비스 정보 수집
  내부 서비스가 인증 없이 동작 (A05 - 보안 설정 오류)
  응답에서 내부 DB 쿼리 파라미터 패턴 발견

Step 3: SQL Injection (A03)
  { "url": "http://internal-service/api/users?id=1 UNION SELECT..." }
  → 내부 서비스의 SQL Injection 취약점을 SSRF를 통해 원격으로 악용
  → 내부 DB 전체 탈취

Step 4: 권한 상승 (A01)
  탈취한 관리자 계정으로 외부 API에서 권한 상승
  → 전체 시스템 제어

방어 포인트:
  - URL 화이트리스트로 SSRF 차단
  - 내부 서비스 간 인증 (mTLS)
  - 내부 서비스에서도 SQL Injection 방어
  - 최소 권한 DB 계정
```

---

## ⚖️ Spring 개발자를 위한 우선순위

| 순위 | 항목 | Spring 핵심 점검 | 즉시 수정 여부 |
|------|------|-----------------|----------------|
| 1 | A01: 접근 제어 | IDOR 방어, @PreAuthorize | 즉시 |
| 2 | A03: 인젝션 | @Query 문자열 연결 | 즉시 |
| 3 | A07: 인증 | JWT 설정, alg 화이트리스트 | 즉시 |
| 4 | A05: 설정 오류 | Actuator 노출 범위 | 즉시 |
| 5 | A02: 암호화 | PasswordEncoder 타입 | 즉시 |
| 6 | A06: 취약 컴포넌트 | 의존성 CVE 스캔 | 주기적 |
| 7 | A10: SSRF | 외부 URL 요청 화이트리스트 | 기능별 |
| 8 | A09: 로깅 | 보안 이벤트 로그 | 점진적 |
| 9 | A04: 안전하지 않은 설계 | 설계 단계 위협 모델링 | 신규 기능부터 |
| 10 | A08: 무결성 | 역직렬화 사용 여부 | 사용 시 즉시 |

---

## 📌 핵심 정리

- **A01(접근 제어)이 2회 연속 1위** — 인증은 있지만 인가의 세부 구현(소유권 검증)을 놓치는 경우가 가장 많다
- **취약점은 연쇄된다** — 단일 취약점보다 여러 취약점이 연결된 공격 체인이 실제 침해로 이어진다
- **Spring Security가 방어해주지 않는 것이 있다** — 프레임워크는 인증/기본 인가를 제공하지만, 비즈니스 로직 수준의 소유권 검증은 개발자 책임이다
- **설정이 코드만큼 중요하다** — A05(설정 오류)는 코드 변경 없이도 심각한 취약점을 만든다

---

## 🤔 생각해볼 문제

**문제 1**: OWASP Top 10에서 "Spring Security를 올바르게 설정하면 방어되는 항목"과 "Spring Security 설정과 무관하게 개발자가 직접 방어해야 하는 항목"을 구분해보라.

**해설**:
```
Spring Security가 방어에 도움이 되는 항목:
  A07 (인증): SecurityFilterChain 설정, JWT 검증
  A05 (설정 오류): Security 기본 헤더 설정
  → 단, 올바른 설정이 전제 조건

개발자가 직접 방어해야 하는 항목:
  A01 (접근 제어): @PreAuthorize + 소유권 검증 = 개발자 책임
  A03 (인젝션): 쿼리 작성 방식 = 개발자 책임
  A02 (암호화): PasswordEncoder 선택 + 민감 데이터 암호화 = 개발자 책임
  A04 (안전하지 않은 설계): 비즈니스 로직 설계 = 개발자/아키텍트 책임
  A10 (SSRF): URL 화이트리스트 구현 = 개발자 책임
  A09 (로깅): 보안 이벤트 로깅 구현 = 개발자 책임
```

**문제 2**: 다음 중 OWASP Top 10에서 가장 오랫동안 상위권을 유지한 취약점과 그 이유를 설명하라.

**해설**:
```
A03 (인젝션): 2010년부터 지속적으로 상위권
이유:
  1. 수십 년간 새로운 형태로 진화 (SQL → LDAP → XML → NoSQL)
  2. 편리함을 위한 문자열 연결 습관
  3. 프레임워크가 바뀌어도 개발자 실수는 반복됨
  4. 새로운 기술 스택마다 새로운 인젝션 패턴 등장

A01 (접근 제어): 2017년 5위 → 2021년/2023년 1위로 상승
이유:
  1. 마이크로서비스 전환으로 API 수가 폭증
  2. API 수가 늘수록 권한 검증 누락 가능성 증가
  3. IDOR은 자동화 도구로 쉽게 탐지/악용 가능
  4. 비즈니스 로직 수준의 방어는 프레임워크가 대신할 수 없음
```

---

<div align="center">

**[⬅️ 이전: 위협 모델링 방법론 — DFD와 PASTA](./02-threat-modeling-dfd-pasta.md)** | **[홈으로 🏠](../README.md)** | **[다음: Defense in Depth — 계층별 방어 설계 ➡️](./04-defense-in-depth.md)**

</div>
