# 보안 개발 생명주기(SDL)

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- SDL(Security Development Lifecycle)은 기존 개발 프로세스와 어떻게 통합되는가?
- 설계/개발/리뷰/배포/운영 단계에서 각각 어떤 보안 활동을 수행해야 하는가?
- PR 코드 리뷰에서 보안 관점으로 무엇을 확인해야 하는가?
- CI/CD 파이프라인에 보안 게이트를 어떻게 추가하는가?
- 운영 중 이상 탐지를 어떻게 자동화하는가?

---

## 🔍 왜 SDL이 실무에서 중요한가

"보안은 나중에"라는 접근 방식의 비용:
- 설계 단계 취약점 수정: 기준 비용 1배
- 개발 중 발견: 6배
- 테스트 단계 발견: 15배
- 프로덕션 배포 후 발견: 30~100배
- 침해 사고 후 수정: 300배 이상 (평판 손실, 법적 비용 포함)

SDL은 보안 활동을 개발 프로세스의 각 단계에 분산시켜 **발견 시점을 앞당기고 수정 비용을 낮추는** 접근 방식이다.

---

## 😱 흔한 실수 (Before — "보안 스프린트"를 별도로 잡는 것)

```
잘못된 접근:
  기능 개발 스프린트 → 기능 개발 스프린트 → ... → 보안 스프린트

문제:
  1. 보안 스프린트 때 발견된 취약점이 이미 출시된 기능에 있음
     → 수정 시 회귀 위험
  2. 보안을 "다른 팀의 일"로 여기게 됨
  3. 출시 일정에 쫓길 때 보안 스프린트가 가장 먼저 삭제됨
  4. 코드베이스에 축적된 보안 부채가 한꺼번에 쏟아짐

올바른 접근:
  각 스프린트의 기능 설계/개발/리뷰/배포에 보안 활동을 내재화
  → 보안은 별도 단계가 아니라 개발 과정의 일부
```

---

## 🔬 단계별 SDL 활동

### Phase 1: 요구사항 및 설계 단계

```
활동 1: 보안 요구사항 정의
  기능 요구사항에 보안 요구사항을 함께 작성

  예시 - 주문 API 기능 요구사항:
    ✓ 인증된 사용자만 주문 생성 가능
    ✓ 사용자는 자신의 주문만 조회 가능 (IDOR 방어)
    ✓ 주문 금액은 서버에서 계산 (클라이언트 변조 방어)
    ✓ 주문 생성/취소 이력은 감사 로그로 저장

활동 2: 위협 모델링 (DFD + STRIDE)
  새 기능의 데이터 흐름을 그리고 신뢰 경계 식별
  각 경계에서 STRIDE 적용 → 위협 목록 → 방어 설계

  소요 시간: 기능 복잡도에 따라 30분~2시간
  산출물: 위협 목록 + 방어 결정 문서

활동 3: 보안 아키텍처 검토
  □ 새 서비스/API가 기존 신뢰 경계를 변경하는가?
  □ 새로운 외부 의존성이 추가되는가?
  □ 민감 데이터 저장/전송이 새로 발생하는가?
  □ 새 DB 계정/권한이 필요한가?
```

---

### Phase 2: 개발 단계

```
개발자 보안 체크리스트 (코딩 시 확인):

인증/인가
  □ 새 엔드포인트에 @PreAuthorize 적용?
  □ PathVariable 리소스 소유자 검증 코드 있음?
  □ 관리자 기능에 ROLE_ADMIN 조건 있음?

입력값 검증
  □ @Valid + Bean Validation 적용?
  □ @Query에 문자열 연결(+) 없음?
  □ 외부 URL을 요청하는 경우 화이트리스트 검증 있음?

에러 처리
  □ 스택 트레이스가 클라이언트 응답에 포함되지 않음?
  □ 에러 응답이 내부 정보(DB 쿼리, 경로 등) 포함 안 함?

암호화
  □ 민감 데이터(PII, 결제 정보)가 평문으로 저장되지 않음?
  □ 비밀번호는 BCrypt/Argon2로 해싱?

로깅
  □ 로그에 비밀번호, 카드번호, 개인정보 없음?
  □ 중요 행위(로그인, 권한 오류, 데이터 변경)에 로그 있음?

비밀정보 관리
  □ 코드에 하드코딩된 비밀번호/API 키 없음?
  □ application.properties에 민감 정보 없음?
    (환경변수 또는 Secrets Manager 사용)
```

---

### Phase 3: 코드 리뷰 단계

```
PR 템플릿 보안 섹션:

## 보안 체크리스트
- [ ] 새 엔드포인트에 인증/인가 적용 여부 확인
- [ ] 입력값 검증 (Bean Validation, 화이트리스트)
- [ ] SQL/JPQL에 파라미터 바인딩 사용
- [ ] 에러 응답에 내부 정보 미포함
- [ ] 민감 데이터 로그 미포함
- [ ] 하드코딩된 비밀번호/API 키 없음
- [ ] 위협 모델에 없던 새 신뢰 경계 없음

리뷰어가 중점적으로 볼 코드:
  1. @Query 어노테이션 → 문자열 연결 확인
  2. findById, findBy... → 결과 소유자 검증 확인
  3. ResponseEntity 반환 → 에러 케이스 응답 확인
  4. log.info/debug → 민감 정보 포함 여부
  5. new URL(), RestTemplate → 외부 URL 요청 화이트리스트

실제 취약 코드 리뷰 예시:
  // 리뷰어가 발견해야 하는 취약점
  @GetMapping("/documents/{id}")
  public Document getDocument(@PathVariable Long id) {
      return documentRepository.findById(id)  // ← IDOR: 소유자 검증 없음
          .orElseThrow(() -> new RuntimeException(   // ← 정보 노출: RuntimeException 메시지
              "Document not found: " + id));          //   에 id 포함
  }
  
  // 올바른 코드
  @GetMapping("/documents/{id}")
  public Document getDocument(@PathVariable Long id,
                              @AuthenticationPrincipal UserDetails user) {
      Document doc = documentRepository.findById(id)
          .orElseThrow(() -> new NotFoundException("Document not found"));
      
      if (!doc.getOwnerId().equals(user.getUserId())) {
          throw new ForbiddenException();
      }
      return doc;
  }
```

---

### Phase 4: CI/CD 파이프라인 보안 게이트

```yaml
# .github/workflows/security.yml

name: Security Gate

on: [push, pull_request]

jobs:
  sast:
    name: Static Analysis
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      # SpotBugs Security Plugin
      - name: Run SpotBugs
        run: ./gradlew spotbugsMain
        # SQL Injection, XSS, 하드코딩 비밀번호 탐지
      
      # 비밀번호/API 키 스캔
      - name: Secret Scanning
        uses: gitleaks/gitleaks-action@v2
        # 코드에 AWS 키, 비밀번호 패턴 탐지
      
      # 의존성 CVE 스캔
      - name: Dependency Check
        run: ./gradlew dependencyCheckAnalyze
        env:
          NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
        # HIGH/CRITICAL CVE 발견 시 빌드 실패
      
      # 컨테이너 이미지 스캔
      - name: Container Scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:${{ github.sha }}
          exit-code: '1'
          severity: 'HIGH,CRITICAL'

  sca:
    name: Software Composition Analysis
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      # OWASP Dependency-Check
      - name: OWASP Dependency Check
        run: |
          ./gradlew dependencyCheckAnalyze
          # 결과 리포트를 PR 코멘트로 게시

게이트 정책:
  HIGH/CRITICAL CVE → 빌드 실패 → PR 머지 차단
  하드코딩된 시크릿 → 빌드 실패 → 즉시 알림
  SpotBugs 보안 버그 → 경고 (팀 설정에 따라 실패로)
```

---

### Phase 5: 배포 및 운영 단계

```
배포 전 체크리스트:

환경 설정
  □ SPRING_PROFILES_ACTIVE=prod
  □ spring.h2.console.enabled=false
  □ management.endpoints.web.exposure.include=health,info
  □ server.error.include-stacktrace=never
  □ spring.jpa.show-sql=false

비밀정보
  □ DB 비밀번호가 환경변수 또는 Secrets Manager에서 주입?
  □ JWT 서명 키가 충분히 길고 랜덤한가? (256비트 이상)
  □ 외부 API 키가 코드에 하드코딩되지 않음?

네트워크
  □ DB가 퍼블릭 서브넷에 배치되지 않음?
  □ 관리자 포트가 인터넷에 노출되지 않음?
  □ HTTPS 인증서 유효 기간 확인?

운영 중 모니터링:

Spring Actuator 보안 메트릭 활용:
  # 인증 실패 카운터
  management.metrics.enable.spring.security=true
  
  # Prometheus + Grafana 대시보드
  - 초당 인증 실패 횟수
  - 권한 오류 발생 비율
  - Rate Limit 초과 요청 수

이상 탐지 알림 규칙:
  rule "BruteForce":
    condition: auth_failures_per_ip > 100 in 5min
    action: Slack 알림 + IP 임시 차단

  rule "IDOR_Attempt":
    condition: authorization_errors_per_user > 50 in 1min
    action: Slack 알림 + 사용자 세션 무효화

  rule "OffHours_Admin":
    condition: admin_api_call AND hour NOT IN [9..18]
    action: PagerDuty 호출 + 담당자 문자
```

---

## 📊 팀 규모별 SDL 도입 로드맵

```
스타트업 (1~5명):
  Week 1:
    - PR 템플릿에 보안 체크리스트 추가
    - application.properties 민감 정보 환경변수로 이동
    - PasswordEncoder → BCrypt 확인
  
  Week 2~4:
    - GitHub Actions에 Gitleaks (비밀번호 스캔) 추가
    - Dependency-Check 추가 (주간 실행)
    - 인증 실패 로그 추가

  Month 2~3:
    - SpotBugs 추가
    - Actuator 설정 점검
    - DB 계정 최소 권한 분리

소규모 팀 (5~20명):
  추가 활동:
    - 새 기능마다 위협 모델링 (30분)
    - 분기별 전체 시스템 DFD 업데이트
    - DAST (OWASP ZAP) 스테이징 환경 자동 스캔
    - 보안 이상 탐지 알림

중규모 팀 (20명+):
  추가 활동:
    - 전담 보안 엔지니어 또는 Security Champion 제도
    - 연간 침투 테스트 (외부 전문 업체)
    - SIEM 도입
    - 버그 바운티 프로그램
```

---

## ⚖️ 트레이드오프

| 활동 | 비용 | 효과 | 우선순위 |
|------|------|------|---------|
| PR 보안 체크리스트 | 매우 낮음 | 중간 (코드 리뷰 강화) | 최우선 |
| CI 비밀번호 스캔 | 낮음 | 높음 (하드코딩 방지) | 최우선 |
| 의존성 CVE 스캔 | 낮음 | 높음 (알려진 취약점) | 높음 |
| SpotBugs SAST | 중간 | 중간 (패턴 기반 탐지) | 높음 |
| 위협 모델링 | 중간 | 매우 높음 (설계 단계 발견) | 높음 |
| DAST (ZAP) | 중간 | 높음 (런타임 탐지) | 중간 |
| 보안 감사 로그 | 중간 | 높음 (탐지/대응) | 중간 |
| 침투 테스트 | 높음 | 매우 높음 (실전 검증) | 성장 후 |

---

## 📌 핵심 정리

- **보안은 별도 단계가 아니다** — 설계/개발/리뷰/배포/운영 각 단계에 보안 활동을 내재화해야 한다
- **발견 시점이 비용을 결정한다** — 설계 단계 발견이 프로덕션 침해 후 수정보다 30~300배 저렴하다
- **자동화로 반복 작업을 제거** — CI 파이프라인의 보안 게이트는 사람이 놓치는 것을 잡는다
- **팀 규모에 맞는 SDL** — 완벽한 SDL이 아니라 현재 팀에서 지속 가능한 SDL을 먼저 시작한다
- **운영 중 모니터링이 2차 방어선** — 방어가 실패했을 때 즉시 탐지하는 구조를 갖춰야 한다

---

## 🤔 생각해볼 문제

**문제 1**: 다음 PR을 보안 리뷰어 관점에서 검토하고, 모든 보안 문제를 찾아라.

```java
// PR: 사용자 프로필 조회 API 추가
@RestController
@RequestMapping("/api/users")
public class UserController {
    
    @GetMapping("/{userId}/profile")
    public UserProfile getProfile(@PathVariable String userId) {
        try {
            return userService.getProfile(userId);
        } catch (Exception e) {
            log.info("Profile fetch error for userId={}: {}", userId, e.getMessage());
            throw new RuntimeException("Error: " + e.getMessage());
        }
    }
    
    @PostMapping("/search")
    public List<User> searchUsers(@RequestParam String query) {
        return userRepository.findByQuery(
            "SELECT * FROM users WHERE name LIKE '%" + query + "%'"
        );
    }
}
```

**해설**:
```
발견된 보안 문제:

1. getProfile: 인증 없음
   - @PreAuthorize 없음 → 비인증 사용자도 호출 가능
   - PathVariable userId 소유자 검증 없음 → IDOR

2. getProfile: 정보 노출
   - 에러 응답에 e.getMessage() 포함 → 내부 정보 노출
   - RuntimeException에 원본 메시지 그대로 전달

3. searchUsers: SQL Injection
   - 문자열 연결로 LIKE 쿼리 생성 → SQL Injection 가능
   - query = "'; DROP TABLE users; --" 입력 가능

4. log.info: PII 로깅 위험
   - userId가 이메일이나 개인식별자인 경우 로그에 PII 기록

수정 코드:
  @GetMapping("/{userId}/profile")
  @PreAuthorize("isAuthenticated()")
  public UserProfile getProfile(
          @PathVariable String userId,
          @AuthenticationPrincipal UserDetails currentUser) {
      if (!userId.equals(currentUser.getUsername())) {
          throw new ForbiddenException();
      }
      return userService.getProfile(userId);
  }
  
  @PostMapping("/search")
  @PreAuthorize("hasRole('ADMIN')")
  public List<User> searchUsers(@RequestParam @Size(max=50) String query) {
      return userRepository.findByNameContaining(query);  // Spring Data로 안전하게
  }
```

**문제 2**: 5명 규모 스타트업에서 "보안 활동을 시작하고 싶지만 시간이 없다"는 상황에서, 하루 30분 투자로 첫 2주 동안 할 수 있는 SDL 활동을 설계하라.

**해설**:
```
Day 1~2 (1시간):
  기존 application.properties에서 비밀번호, API 키를 환경변수로 이동
  .gitignore에 .env 추가
  → 즉시 효과: 하드코딩 비밀번호 제거

Day 3~4 (30분):
  GitHub Actions에 Gitleaks 추가 (5분 설정)
  → 이후 모든 PR에서 하드코딩 자동 검사

Day 5~7 (1시간):
  PR 템플릿에 보안 체크리스트 5개 항목 추가
  팀에 공유 + 설명

Week 2 (각 30분):
  Day 8: PasswordEncoder 설정 확인 + BCrypt로 통일
  Day 9: Actuator 설정 점검 + 프로덕션 노출 범위 최소화
  Day 10: DB 계정 권한 확인 (읽기 전용 계정 분리 계획 수립)
  Day 11: 의존성 CVE 스캔 (gradlew dependencyCheckAnalyze 첫 실행)
  Day 12: 결과 검토 + CRITICAL 항목 업데이트 계획

결과:
  2주 후 달성:
  ✓ 하드코딩 비밀번호 제거
  ✓ CI 비밀번호 스캔 자동화
  ✓ PR 보안 리뷰 체계
  ✓ 설정 오류 점검 완료
  ✓ 의존성 취약점 현황 파악

  총 투자 시간: 약 5~6시간
  비용: 무료 (모두 오픈소스 도구)
```

---

<div align="center">

**[⬅️ 이전: Defense in Depth — 계층별 방어 설계](./04-defense-in-depth.md)** | **[홈으로 🏠](../README.md)** | **[다음: Chapter 2 — SQL Injection 원리 ➡️](../injection-attacks/01-sql-injection-principles.md)**

</div>
