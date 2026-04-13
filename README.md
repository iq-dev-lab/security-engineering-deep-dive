<div align="center">

# 🔐 Security Engineering Deep Dive

**"보안 설정을 복붙하는 것과, 공격 원리를 알고 방어를 설계하는 것은 다르다"**

<br/>

> *"`@PreAuthorize` 붙이고 JWT 필터 설정했으니 안전하겠지 — 와 — SQL Injection이 PreparedStatement를 우회하는 조건, JWT alg:none 공격이 서명 검증을 무력화하는 원리, SSRF로 내부망을 탈출하는 방법을 알고 방어 코드를 설계하는 것의 차이를 만드는 레포"*

공격자 관점에서 내 시스템의 취약점을 먼저 찾고, OWASP Top 10의 표면적 대책이 아닌 근본 원인을 이해하며, Spring Security 설정의 흔한 실수가 어떤 공격 벡터에 노출되는지,  
**"왜 이 설정이 이 공격을 막는가"** 라는 질문으로 백엔드 보안을 끝까지 파헤칩니다

<br/>

[![GitHub](https://img.shields.io/badge/GitHub-dev--book--lab-181717?style=flat-square&logo=github)](https://github.com/dev-book-lab)
[![Spring Security](https://img.shields.io/badge/Spring_Security-6.x-6DB33F?style=flat-square&logo=spring&logoColor=white)](https://docs.spring.io/spring-security/reference/)
[![OWASP](https://img.shields.io/badge/OWASP_Top_10-2023-C0392B?style=flat-square)](https://owasp.org/Top10/)
[![Docs](https://img.shields.io/badge/Docs-41개-blue?style=flat-square&logo=readthedocs&logoColor=white)](./README.md)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square&logo=opensourceinitiative&logoColor=white)](./LICENSE)

</div>

---

## 🎯 이 레포에 대하여

보안에 관한 자료는 넘쳐납니다. 하지만 대부분은 **"어떤 설정을 켜야 하는가"** 에서 멈춥니다.

| 일반 자료 | 이 레포 |
|----------|---------|
| "PreparedStatement를 쓰면 SQL Injection이 막힙니다" | 문자열 연결 쿼리가 어떻게 공격 표면이 되는지, UNION 기반 데이터 추출 원리, JPA `@Query`에서도 네이티브 쿼리와 SpEL이 취약한 조건 |
| "JWT를 쓰면 인증이 됩니다" | `alg:none` 공격이 서명 검증을 무력화하는 원리, `RS256 → HS256` 알고리즘 혼동 공격, `kid` 헤더 인젝션, Spring Security 설정의 어느 부분이 이를 막는가 |
| "Spring Security의 CSRF 보호를 활성화하세요" | Same-Origin Policy를 우회하는 form submission 방식, SameSite 쿠키가 CSRF를 막는 원리, REST API에서 CSRF 토큰을 끄는 정확한 조건 |
| "HTTPS를 쓰세요" | HSTS가 SSL Strip 공격을 막는 원리, `Strict-Transport-Security` 헤더의 `includeSubDomains` / `preload` 옵션이 실제로 하는 일 |
| "입력값을 검증하세요" | XSS가 `Content-Type: application/json` 응답에서도 발생하는 조건, CSP `script-src 'self'`가 외부 스크립트를 차단하는 원리 |
| "SSRF를 막으려면 URL을 검증하세요" | 서버가 `169.254.169.254`를 요청하게 만드는 방법, AWS 임시 자격증명 탈취 → S3/RDS 전체 접근 시나리오, IMDSv2가 이를 막는 방식 |
| 이론 나열 | 취약한 Before 코드 → 공격 페이로드 → 안전한 After 코드, Docker Compose 실험 환경(WebGoat + OWASP ZAP), 실제 CVE 사례 |

---

## 🔗 선행 학습 연결

이 레포는 다음 레포의 지식을 전제로 합니다.

| 레포 | 연결 지점 |
|-----|-----------|
| [spring-security-deep-dive](../spring-security-deep-dive) | 인증 필터 체인 구조 이해 — 방어 코드가 어느 레이어에서 동작하는지 맥락 파악 필수 |
| [network-deep-dive](../network-deep-dive) | HTTPS/TLS 핸드셰이크, HTTP 헤더 동작 원리 — XSS/CSRF/Clickjacking 방어 헤더 완전 이해 |
| [database-internals](../database-internals) | SQL 실행 엔진 원리 — SQL Injection이 파서 레벨에서 어떻게 작동하는지 완전 이해 |

---

## 🚀 빠른 시작

각 챕터의 첫 문서부터 바로 학습을 시작하세요!

[![Ch1](https://img.shields.io/badge/🔹_Ch1-공격자_관점_전환과_STRIDE-C0392B?style=for-the-badge)](./security-mindset-threat-modeling/01-attacker-mindset-stride.md)
[![Ch2](https://img.shields.io/badge/🔹_Ch2-SQL_Injection_원리-C0392B?style=for-the-badge)](./injection-attacks/01-sql-injection-principles.md)
[![Ch3](https://img.shields.io/badge/🔹_Ch3-JWT_취약점_완전_분해-C0392B?style=for-the-badge)](./authentication-session/01-jwt-vulnerabilities.md)
[![Ch4](https://img.shields.io/badge/🔹_Ch4-XSS_3가지_유형-C0392B?style=for-the-badge)](./web-vulnerabilities/01-xss-types.md)
[![Ch5](https://img.shields.io/badge/🔹_Ch5-IDOR_공격과_소유권_검증-C0392B?style=for-the-badge)](./access-control/01-idor-ownership-check.md)
[![Ch6](https://img.shields.io/badge/🔹_Ch6-SSRF와_클라우드_메타데이터_탈취-C0392B?style=for-the-badge)](./ssrf-data-exposure/01-ssrf-cloud-metadata.md)
[![Ch7](https://img.shields.io/badge/🔹_Ch7-SAST_정적_분석_자동화-C0392B?style=for-the-badge)](./security-testing-operations/01-sast-pipeline.md)

---

## 📚 전체 학습 지도

> 💡 각 섹션을 클릭하면 상세 문서 목록이 펼쳐집니다

<br/>

### 🔹 Chapter 1: 보안 사고방식과 위협 모델링

> **핵심 질문:** 공격자는 어떻게 생각하는가? 내 시스템의 가장 위험한 진입점은 어디인가? 위협 모델링으로 설계 단계에서 취약점을 어떻게 제거하는가?

<details>
<summary><b>STRIDE 위협 모델부터 보안 개발 생명주기까지 (5개 문서)</b></summary>

<br/>

| 문서 | 다루는 내용 |
|------|------------|
| [01. 공격자 관점 전환 — STRIDE 위협 모델](./security-mindset-threat-modeling/01-attacker-mindset-stride.md) | 방어자가 아닌 공격자로 생각해야 하는 이유, STRIDE(Spoofing/Tampering/Repudiation/Info Disclosure/DoS/Elevation) 각 항목이 실제 Spring 서비스에서 어떻게 나타나는지, 내 시스템에서 가장 위험한 진입점 찾기 |
| [02. 위협 모델링 방법론 — DFD와 PASTA](./security-mindset-threat-modeling/02-threat-modeling-dfd-pasta.md) | DFD(Data Flow Diagram)로 공격 표면을 시각화하는 방법, PASTA(Process for Attack Simulation and Threat Analysis) 7단계 방법론, 위험 우선순위 평가(가능성 × 영향도) |
| [03. OWASP Top 10 2023 개요 — 비즈니스 영향 분석](./security-mindset-threat-modeling/03-owasp-top10-overview.md) | 10가지 취약점의 실제 발생 빈도와 비즈니스 영향(데이터 유출/서비스 중단/규제 처벌), 취약점 간 연쇄 공격 경로(SSRF → 내부망 SQL Injection), 각 항목별 Spring 적용점 |
| [04. Defense in Depth — 계층별 방어 설계](./security-mindset-threat-modeling/04-defense-in-depth.md) | 단일 방어선의 한계(WAF만으로는 부족한 이유), 네트워크/애플리케이션/데이터 레이어 계층 방어 설계, Security by Default 원칙과 Spring Security 기본 설정이 켜는 것들 |
| [05. 보안 개발 생명주기(SDL)](./security-mindset-threat-modeling/05-security-development-lifecycle.md) | 설계 단계 위협 모델링 체크리스트, PR 코드 리뷰 보안 체크리스트(SQL Injection/XSS/인증 누락), CI 파이프라인 보안 게이트, 운영 중 이상 탐지 |

</details>

<br/>

### 🔹 Chapter 2: 인젝션 공격 완전 분해

> **핵심 질문:** SQL Injection은 어떻게 DB 전체를 탈취하는가? JPA/JPQL도 취약한 조건은 무엇인가? 인젝션이 SQL에만 국한되지 않는 이유는?

<details>
<summary><b>SQL Injection 원리부터 실전 취약점 재현까지 (7개 문서)</b></summary>

<br/>

| 문서 | 다루는 내용 |
|------|------------|
| [01. SQL Injection 원리 — 쿼리 구조를 부수는 방법](./injection-attacks/01-sql-injection-principles.md) | 문자열 연결 쿼리가 어떻게 공격 표면이 되는가, `' OR '1'='1`이 WHERE 절을 무력화하는 DB 파서 레벨 원리, UNION 기반 데이터 추출로 스키마 구조를 노출하는 방법 |
| [02. Blind SQL Injection — 에러 없이 데이터를 훔치는 방법](./injection-attacks/02-blind-sql-injection.md) | 에러 메시지가 없을 때 시간 기반(`SLEEP()`)으로 데이터를 1비트씩 추출하는 방법, 불리언 기반 추출(참/거짓 응답 차이), Spring/JPA 서비스에서 발생하는 조건 |
| [03. JPA/JPQL에서의 SQL Injection — ORM이 막아주지 않는 것](./injection-attacks/03-jpa-jpql-injection.md) | `@Query("SELECT u FROM User u WHERE u.name = '" + name + "'")` 취약 패턴, Native Query의 문자열 연결 위험, SpEL 표현식 인젝션, 완전한 방어 코드(파라미터 바인딩) |
| [04. 명령어 인젝션 — OS가 공격자의 명령을 실행하는 원리](./injection-attacks/04-command-injection.md) | `Runtime.exec(userInput)`이 위험한 이유, 셸 메타문자(`;`, `|`, `&&`)로 명령어를 연결하는 방법, ProcessBuilder를 이용한 안전한 외부 프로세스 실행 패턴 |
| [05. LDAP/XML/NoSQL 인젝션 — 인젝션은 SQL에만 있지 않다](./injection-attacks/05-ldap-xml-nosql-injection.md) | MongoDB `$where` 연산자 인젝션, XXE(XML External Entity) 공격으로 서버 파일을 읽는 원리, LDAP 필터 인젝션, 각 벡터별 방어 설계 |
| [06. 인젝션 방어 원칙 — PreparedStatement부터 최소 권한까지](./injection-attacks/06-injection-defense-principles.md) | PreparedStatement/파라미터 바인딩이 SQL 구조 변경을 막는 원리, 입력값 화이트리스트 vs 블랙리스트 한계, 최소 권한 DB 계정(SELECT 전용), ORM 안전 사용 패턴 정리 |
| [07. 실전 취약점 재현 — WebGoat Docker 환경](./injection-attacks/07-lab-sqli-reproduction.md) | Docker Compose로 WebGoat + 취약 Spring 앱 구동, SQL Injection 단계별 실습(에러 기반 → UNION 기반 → Blind), sqlmap 자동화 실습, 방어 코드 Before/After 검증 |

</details>

<br/>

### 🔹 Chapter 3: 인증과 세션 취약점

> **핵심 질문:** JWT alg:none 공격은 어떻게 서명 검증을 무력화하는가? 세션 고정 공격과 CSRF의 원리는 무엇이고 Spring Security는 어떻게 막는가?

<details>
<summary><b>JWT 취약점부터 비밀번호 저장 설계까지 (7개 문서)</b></summary>

<br/>

| 문서 | 다루는 내용 |
|------|------------|
| [01. JWT 취약점 완전 분해 — alg:none부터 kid 인젝션까지](./authentication-session/01-jwt-vulnerabilities.md) | `alg:none` 공격(서명 없이 토큰 위조), `RS256 → HS256` 알고리즘 혼동 공격(공개키를 HMAC 비밀키로 오용), `kid` 헤더 인젝션으로 서명 키를 교체하는 방법, 실제 라이브러리 취약점 CVE 사례 |
| [02. JWT 안전한 구현 — Spring Security 설정의 취약점](./authentication-session/02-jwt-secure-implementation.md) | 알고리즘 명시적 화이트리스트(`requireAlgorithm`), 서명 키와 검증 키 분리, 만료 시간 강제 검증 누락 사례, Spring Security `JwtDecoder` 설정에서 놓치기 쉬운 취약점 |
| [03. 세션 고정 공격 — 로그인 전 세션을 탈취하는 방법](./authentication-session/03-session-fixation.md) | 공격자가 로그인 전 세션 ID를 피해자에게 심어두고 인증 후 탈취하는 원리, Spring Security의 `sessionFixation().changeSessionId()` 방어 동작 방식, 세션 관련 보안 설정 완전 가이드 |
| [04. CSRF 공격 — Same-Origin Policy의 허점](./authentication-session/04-csrf-attack.md) | SOP(Same-Origin Policy)를 우회하는 form submission 방식, `SameSite=Strict/Lax` 쿠키 속성이 CSRF를 막는 원리, REST API에서 CSRF 토큰을 끄는 정확한 조건과 위험 |
| [05. OAuth2 취약점 — state 파라미터와 오픈 리다이렉트](./authentication-session/05-oauth2-vulnerabilities.md) | `state` 파라미터 없는 Authorization Code Flow의 CSRF 공격, 오픈 리다이렉트를 통한 Authorization Code 탈취 시나리오, PKCE 없는 Public Client의 위험성, Spring Security OAuth2 설정 점검 |
| [06. 브루트포스와 계정 보호 — Rate Limiting 설계](./authentication-session/06-bruteforce-account-protection.md) | Rate Limiting 없는 로그인 API가 공격에 노출되는 방식, Exponential Backoff vs 고정 잠금의 트레이드오프, 계정 잠금 정책이 DoS가 되는 역설, Redis 슬라이딩 윈도우로 Rate Limiter 구현 |
| [07. 비밀번호 저장 — MD5의 실패와 Bcrypt/Argon2의 설계](./authentication-session/07-password-storage.md) | MD5/SHA-1이 Rainbow Table에 취약한 이유(역방향 연산 가능), Bcrypt의 솔트와 Cost Factor가 무차별 대입을 느리게 만드는 원리, Argon2의 메모리 하드 함수 설계, Spring Security `PasswordEncoder` 내부 동작 |

</details>

<br/>

### 🔹 Chapter 4: 웹 취약점 (XSS, Clickjacking, Open Redirect)

> **핵심 질문:** XSS는 백엔드 문제인가 프론트엔드 문제인가? CSP는 스크립트 실행을 어떻게 제한하는가? 보안 HTTP 헤더는 각각 무엇을 막는가?

<details>
<summary><b>XSS 유형 분석부터 보안 HTTP 헤더 완전 가이드까지 (6개 문서)</b></summary>

<br/>

| 문서 | 다루는 내용 |
|------|------------|
| [01. XSS 3가지 유형 — Reflected/Stored/DOM-based](./web-vulnerabilities/01-xss-types.md) | Reflected XSS(요청에 삽입된 스크립트 반사), Stored XSS(DB에 저장된 스크립트 실행), DOM-based XSS(서버 무관 클라이언트 파싱 취약점)의 공격 벡터 차이, `document.cookie` 탈취 → 세션 하이재킹 흐름 |
| [02. 백엔드 개발자의 XSS 방어 책임](./web-vulnerabilities/02-backend-xss-defense.md) | API 응답 `Content-Type: application/json` 강제가 XSS를 막는 원리, `X-Content-Type-Options: nosniff` 헤더의 역할, 서버사이드 렌더링(Thymeleaf)에서 HTML 이스케이핑 누락 사례, Spring 응답 헤더 설정 |
| [03. CSP(Content Security Policy) — 스크립트 실행 도메인 제한](./web-vulnerabilities/03-content-security-policy.md) | `script-src 'self'`가 외부 스크립트를 차단하는 원리, `unsafe-inline`을 허용하면 CSP가 무력화되는 이유, `nonce` 기반 CSP로 인라인 스크립트를 안전하게 허용하는 방법, CSP 위반 리포트 수집 |
| [04. Clickjacking — iframe으로 클릭을 가로채는 방법](./web-vulnerabilities/04-clickjacking.md) | 투명 `<iframe>`으로 페이지를 겹쳐 클릭을 유도하는 공격 원리, `X-Frame-Options: DENY`와 CSP `frame-ancestors 'none'`의 차이, Spring Security에서 Clickjacking 방어 설정 |
| [05. 보안 HTTP 헤더 완전 가이드](./web-vulnerabilities/05-security-http-headers.md) | `Strict-Transport-Security`(HSTS)가 SSL Strip을 막는 원리, `X-XSS-Protection`, `Referrer-Policy`, `Permissions-Policy` 각 헤더의 실제 동작, Spring Security `headers()` DSL로 한 번에 설정하는 방법 |
| [06. Open Redirect — 로그인 후 리다이렉트 조작](./web-vulnerabilities/06-open-redirect.md) | 로그인 성공 후 `redirect_uri` 파라미터를 공격자가 조작하여 피싱 사이트로 유도하는 방법, 도메인 검증 우회 기법(`https://evil.com/https://trusted.com`), 화이트리스트 기반 방어 설계 |

</details>

<br/>

### 🔹 Chapter 5: 접근 제어와 권한 취약점

> **핵심 질문:** IDOR은 왜 권한 체크를 통과하는가? Mass Assignment로 일반 사용자가 어떻게 관리자가 되는가? Spring Security `@PreAuthorize`의 맹점은?

<details>
<summary><b>IDOR부터 최소 권한 원칙 적용까지 (6개 문서)</b></summary>

<br/>

| 문서 | 다루는 내용 |
|------|------------|
| [01. IDOR — 소유권 검증 없는 API의 위험](./access-control/01-idor-ownership-check.md) | `/api/orders/12345`에서 다른 사용자의 주문을 조회하는 공격, 인증(Authentication)과 인가(Authorization) 혼동이 만드는 취약점, Spring Security에서 소유권 검증을 강제하는 패턴 |
| [02. 수평적 vs 수직적 권한 상승](./access-control/02-horizontal-vertical-privilege-escalation.md) | 일반 사용자가 다른 사용자의 데이터에 접근하는 수평적 권한 상승, 일반 사용자가 관리자 기능을 호출하는 수직적 권한 상승, `@PreAuthorize("@ownerChecker.check(#id)")` 커스텀 권한 검증 |
| [03. Mass Assignment — JSON 필드로 권한을 주입하는 방법](./access-control/03-mass-assignment.md) | 요청 JSON의 `"role": "ADMIN"` 필드가 엔티티를 덮어쓰는 원리, `@JsonIgnore` / Request DTO 분리로 방어하는 방법, Spring `@ModelAttribute`에서 발생하는 같은 패턴 |
| [04. API Rate Limiting 설계 — 엔드포인트별 차등 한도](./access-control/04-api-rate-limiting.md) | 로그인/결제/일반 조회 API의 한도를 다르게 설정해야 하는 이유, Redis 슬라이딩 윈도우 Rate Limiter 구현, 사용자 기반 vs IP 기반 제한의 트레이드오프, 429 응답 설계 |
| [05. JWT 권한 클레임 검증 — roles/scope 누락이 만드는 구멍](./access-control/05-jwt-claims-validation.md) | `roles`, `scope` 클레임 검증을 서버에서 재확인하지 않을 때 권한 상승이 가능한 시나리오, 토큰 탈취 후 클레임 변조 공격, 서버 측 권한 재검증 원칙 |
| [06. 최소 권한 원칙 — DB/IAM/메서드 보안 계층 설계](./access-control/06-least-privilege-principle.md) | DB 계정 권한 최소화(SELECT 전용 계정 분리), AWS IAM 역할 범위 제한(와일드카드 정책의 위험), Spring Security 메서드 보안(`@PreAuthorize`, `@PostFilter`)을 계층적으로 설계하는 방법 |

</details>

<br/>

### 🔹 Chapter 6: SSRF, 민감 데이터 노출, 설정 오류

> **핵심 질문:** SSRF는 어떻게 클라우드 자격증명을 탈취하는가? 민감 데이터가 로그와 에러 응답에 노출되는 패턴은? Spring Actuator를 프로덕션에 열면 무슨 일이 일어나는가?

<details>
<summary><b>SSRF 클라우드 공격부터 의존성 취약점 관리까지 (5개 문서)</b></summary>

<br/>

| 문서 | 다루는 내용 |
|------|------------|
| [01. SSRF — 서버를 통해 내부망을 공격하는 방법](./ssrf-data-exposure/01-ssrf-cloud-metadata.md) | 공격자가 지정한 URL을 서버가 요청하게 만드는 원리, `169.254.169.254` AWS 메타데이터 서비스로 IAM 자격증명 탈취 → S3/RDS 전체 접근 시나리오, IMDSv2 강제로 방어하는 방법 |
| [02. 민감 데이터 노출 — 로그/에러/Git에서 새는 정보](./ssrf-data-exposure/02-sensitive-data-exposure.md) | 로그에 개인정보/카드번호가 남는 패턴, Spring 예외 응답에 스택 트레이스 포함이 공격 정보를 주는 이유, `application.properties` 자격증명을 Git에 커밋하는 사고 예방 |
| [03. 암호화 설계 — AES/RSA 사용 시나리오와 키 관리](./ssrf-data-exposure/03-encryption-design.md) | AES-256-GCM(대칭키)과 RSA(비대칭키) 사용 시나리오 구분, AES-ECB가 패턴을 노출하는 Penguin 공격, 암호화 키를 코드에 박지 않고 AWS KMS/HashiCorp Vault로 관리하는 방법 |
| [04. 보안 설정 오류 — Actuator/CORS/H2 Console](./ssrf-data-exposure/04-security-misconfiguration.md) | Spring Actuator `/actuator/env` 프로덕션 노출로 자격증명이 유출되는 경로, `allowedOrigins("*")` + `allowCredentials(true)` 조합이 왜 위험한가, H2 Console 프로덕션 활성화 사고 |
| [05. 의존성 취약점 관리 — CVE 모니터링과 자동화](./ssrf-data-exposure/05-dependency-vulnerability-management.md) | CVE(Common Vulnerabilities and Exposures) 모니터링 체계, `./gradlew dependencyCheckAnalyze`로 취약 라이브러리 탐지, Trivy 컨테이너 이미지 스캔, Dependabot/Renovate 자동 업데이트 전략 |

</details>

<br/>

### 🔹 Chapter 7: 보안 테스트와 운영 보안

> **핵심 질문:** SAST/DAST는 어떻게 코드에서 취약점을 자동 탐지하는가? 침투 테스트는 어떻게 수행하는가? 보안 인시던트 발생 시 초기 대응은?

<details>
<summary><b>정적 분석 파이프라인부터 인시던트 대응까지 (5개 문서)</b></summary>

<br/>

| 문서 | 다루는 내용 |
|------|------------|
| [01. SAST 자동화 — CI 파이프라인에 보안 게이트 추가](./security-testing-operations/01-sast-pipeline.md) | SpotBugs Security Plugin으로 SQL Injection/XSS 패턴을 정적 분석하는 방법, SonarQube 보안 규칙 설정, GitHub Actions CI 파이프라인에서 보안 게이트로 PR을 차단하는 구성 |
| [02. DAST — OWASP ZAP으로 실행 중인 앱 자동 스캔](./security-testing-operations/02-dast-owasp-zap.md) | OWASP ZAP을 Docker로 구동하여 실행 중인 Spring 앱의 취약점을 자동 탐지하는 방법, Active Scan vs Passive Scan 차이, 주요 취약점 탐지 결과 해석, CI 통합 |
| [03. 침투 테스트 방법론 — Recon부터 Post-Exploitation까지](./security-testing-operations/03-penetration-testing.md) | Reconnaissance → Scanning → Exploitation → Post-Exploitation 단계별 수행 방법, Spring 앱 대상 주요 공격 벡터 점검 체크리스트, 버그 바운티 보고서 작성법 |
| [04. 보안 로깅과 모니터링 — SIEM과 이상 탐지](./security-testing-operations/04-security-logging-monitoring.md) | SIEM(Security Information and Event Management) 이벤트 수집 설계, 비정상 로그인 시도/대량 데이터 조회 패턴 감지, Spring AOP로 보안 이벤트를 로깅하는 방법, 로그 탬퍼링 방지 |
| [05. 인시던트 대응 — 침해 사고 초기 대응과 복구](./security-testing-operations/05-incident-response.md) | 침해 사고 발생 시 초기 대응 절차(격리 → 분석 → 복구 → 공지), 포렌식 로그 보존 원칙, 개인정보보호법/신용정보법상 사용자 공지 의무, 사후 분석(Post-Mortem) 작성법 |

</details>

<br/>

---

## 🧪 실험 환경

> 모든 실습은 아래 Docker Compose 환경에서 재현 가능합니다

```yaml
# docker-compose.yml
services:
  vulnerable-app:
    build:
      context: ./vulnerable-spring-app
    ports:
      - "8080:8080"
    environment:
      SPRING_PROFILES_ACTIVE: vulnerable  # 취약한 설정

  secure-app:
    build:
      context: ./secure-spring-app
    ports:
      - "8081:8081"
    environment:
      SPRING_PROFILES_ACTIVE: secure      # 방어 설정

  mysql:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: root
      MYSQL_DATABASE: security_test

  webgoat:
    image: webgoat/goatandwolf:latest
    ports:
      - "9090:9090"   # 취약점 학습 플랫폼

  owasp-zap:
    image: ghcr.io/zaproxy/zaproxy:stable
    command: zap-webswing.sh
    ports:
      - "8090:8090"   # ZAP GUI
      - "8091:8091"   # ZAP API
```

```bash
# 보안 테스트 핵심 명령어

# SQL Injection 탐지
sqlmap -u "http://localhost:8080/api/users?id=1" --dbs

# JWT alg:none 공격 재현
echo "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9." | \
  python3 -c "import sys,base64; print(base64.b64decode(sys.stdin.readline().split('.')[1]+'=='))"

# OWASP ZAP 자동 스캔
docker exec owasp-zap zap-cli --zap-url http://localhost:8090 \
  active-scan http://localhost:8080

# 컨테이너 이미지 취약점 스캔
trivy image myapp:latest --severity HIGH,CRITICAL

# 의존성 취약점 확인 (Gradle)
./gradlew dependencyCheckAnalyze
```

---

## 📚 참고 자료

- [OWASP Top 10 2023](https://owasp.org/Top10/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — 무료 실습
- [HackTricks](https://book.hacktricks.xyz/) — 공격 기법 레퍼런스
- [JWT 취약점 분석](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- The Web Application Hacker's Handbook (Stuttard & Pinto)

---

<div align="center">

**"보안은 기능이 아니라 설계다"**  
*공격 원리를 모르면 방어 설정이 무엇을 막는지 설명할 수 없다*

</div>
