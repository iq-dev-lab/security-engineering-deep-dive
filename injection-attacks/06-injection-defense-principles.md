# 인젝션 방어 원칙: 안전한 아키텍처 설계

---

## 🎯 핵심 질문

PreparedStatement가 SQL Injection을 방어하는 내부 메커니즘은 무엇인가? 왜 화이트리스트는 보안이고 블랙리스트는 위험한가? 최소 권한 원칙이 인젝션 방어에 어떻게 적용되는가? ORM과 ORD를 안전하게 사용하는 기본 패턴은 무엇인가?

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

**방어 원칙 미숙**: 많은 개발자가 특정 프레임워크나 라이브러리에 의존하면서 **근본적인 원리를 모름**. 새로운 기술이 나타나면 또 같은 실수 반복.

2018년 Equifax 데이터 유출: 1억 4,700만 명 개인정보 탈취. Apache Struts의 OGNL(Object-Graph Navigation Language) Injection 취약점 악용. 개발자가 프레임워크의 보안 기능을 제대로 사용하지 않음.

2015년 ORM Injection 웨이브: Hibernate, JPA 사용하는 프로젝트에서 문자열 연결로 동적 쿼리 생성. 개발자는 "ORM을 쓰니까 안전하다"고 착각.

한국 은행 시스템: 데이터베이스 계정이 DBA 권한(모든 테이블 접근/변조 가능). SQL Injection 발생 시 고객 전체 계좌정보 탈취 가능.

**실무 위험성**:
- 패턴 모르면 새로운 기술도 같은 실수 반복
- 레이어 사이에서 인젝션 발생 (API → 캐시, 캐시 → DB 등)
- 최소 권한 원칙 미적용으로 피해 확대
- 입력 검증만으로 방어 시도 (근본 해결 아님)

## 😱 취약한 아키텍처 (Before)

```
❌ 일반적인 실수:

1. 모든 계층에서 문자열 연결
┌─────────────────────────────────────────┐
│ Controller (String concat)              │ ← SQL 문자열 생성
│   ↓                                     │
│ Service (String concat)                 │ ← 또 문자열 연결
│   ↓                                     │
│ Repository (String concat)              │ ← 또또 문자열 연결
│   ↓                                     │
│ Database (SQL Injection)                │ ← 공격 성공
└─────────────────────────────────────────┘

2. 입력 검증에만 의존
┌─────────────────────────────────────────┐
│ if (input.length() < 100) {             │ ← 길이 검증만
│   String sql = "SELECT * FROM users     │
│                WHERE name = '" +        │
│                input + "'";             │ ← 여전히 취약!
│ }                                       │
└─────────────────────────────────────────┘

3. 최소 권한 원칙 미적용
┌─────────────────────────────────────────┐
│ 애플리케이션 데이터베이스 계정:         │
│ - 권한: SELECT, INSERT, UPDATE, DELETE  │
│ - 대상: 모든 테이블 (admin 테이블도 포함)
│ - 결과: SQL Injection 시 전체 DB 접근   │
└─────────────────────────────────────────┘

4. 동적 언어의 eval() 사용
┌─────────────────────────────────────────┐
│ eval("SELECT * FROM users WHERE " +     │
│      userInput)                         │ ← 최악의 실수
└─────────────────────────────────────────┘
```

### 취약한 코드의 연쇄 효과

```java
// 1단계: Controller에서 입력 받음
@PostMapping("/search")
public List<User> search(@RequestParam String query) {
    return userService.searchUsers(query);
}

// 2단계: Service에서 SQL 문자열 연결
@Service
public class UserService {
    public List<User> searchUsers(String query) {
        String jpql = "SELECT u FROM User u WHERE u.name LIKE '%" + query + "%'";
        return userRepository.customSearch(jpql);
    }
}

// 3단계: Repository에서 실행
@Repository
public class UserRepository {
    public List<User> customSearch(String jpql) {
        Query q = entityManager.createQuery(jpql);  // 이미 손상됨
        return q.getResultList();
    }
}

// 4단계: 공격
// query = "' UNION SELECT u FROM admin_users u WHERE '1'='1"
// 최종 JPQL: SELECT u FROM User u WHERE u.name LIKE '%' UNION SELECT u FROM admin_users u WHERE '1'='1%'
// 결과: admin_users 테이블 전체 조회
```

## ✨ 방어 원칙 기반 아키텍처 (After)

```java
// [방어] 계층별로 일관된 원칙 적용
public class SecureArchitecture {
    
    // ====== 원칙 1: 파라미터 바인딩 (SQL 구조 고정) ======
    
    @RestController
    @RequestMapping("/api/users")
    public class UserController {
        @Autowired
        private UserService userService;
        
        @GetMapping("/search")
        public ResponseEntity<List<UserDTO>> search(@RequestParam String query) {
            // 1. Controller: 입력 검증 (빠른 실패)
            if (query == null || query.length() > 100) {
                return ResponseEntity.badRequest().build();
            }
            
            // 2. Service 호출 (검증된 입력)
            List<User> results = userService.searchUsers(query);
            
            // 3. DTO 변환 (응답)
            return ResponseEntity.ok(results.stream()
                .map(this::toDTO)
                .collect(Collectors.toList()));
        }
    }
    
    @Service
    public class UserService {
        @Autowired
        private UserRepository userRepository;
        
        public List<User> searchUsers(String query) {
            // Service: 비즈니스 로직만 처리 (SQL 생성 아님)
            // Repository에 위임
            return userRepository.findByNameContaining(query);
        }
    }
    
    @Repository
    public interface UserRepository extends JpaRepository<User, Long> {
        // Repository: 선언적 쿼리 (SQL 문자열 연결 없음)
        
        // 원칙 1: 메서드명 쿼리 (가장 안전)
        List<User> findByNameContainingIgnoreCase(String name);
        
        // 원칙 2: @Query + 파라미터 바인딩
        @Query("SELECT u FROM User u WHERE u.name LIKE %:name% " +
               "ORDER BY u.createdAt DESC")
        List<User> searchByName(@Param("name") String name);
        
        // 원칙 3: Criteria API (동적 쿼리)
        default List<User> searchWithCriteria(String name, String email) {
            CriteriaBuilder cb = entityManager.getCriteriaBuilder();
            CriteriaQuery<User> cq = cb.createQuery(User.class);
            Root<User> user = cq.from(User.class);
            
            List<Predicate> predicates = new ArrayList<>();
            
            if (name != null && !name.isEmpty()) {
                predicates.add(cb.like(user.get("name"), "%" + name + "%"));
            }
            
            if (email != null && !email.isEmpty()) {
                predicates.add(cb.equal(user.get("email"), email));
            }
            
            cq.where(predicates.toArray(new Predicate[0]));
            return entityManager.createQuery(cq).getResultList();
        }
    }
    
    // ====== 원칙 2: 입력 검증 (화이트리스트) ======
    
    @Component
    public class InputValidator {
        
        // ❌ 나쁜 예: 블랙리스트 (우회 가능)
        public boolean isValidBlacklist(String input) {
            return !input.contains("'")
                && !input.contains(";")
                && !input.contains("--")
                && !input.contains("/*");
            // SQL 메타문자만 차단 → 다른 공격 벡터 존재
        }
        
        // ✅ 좋은 예: 화이트리스트 (우회 불가)
        public boolean isValidWhitelist(String input) {
            // 알파벳, 숫자, 기본 특수문자만 허용
            return input.matches("^[a-zA-Z0-9\\s._@-]{1,100}$");
        }
        
        // 역할별 검증
        public boolean isValidUsername(String username) {
            // 사용자명: 알파벳, 숫자, 언더스코어 (3-20자)
            return username.matches("^[a-zA-Z0-9_]{3,20}$");
        }
        
        public boolean isValidEmail(String email) {
            // 이메일: RFC 5322 기본 형식
            return email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}$");
        }
        
        public boolean isValidBitrate(String bitrate) {
            // 비트레이트: 숫자 + k/m (100~50000)
            if (!bitrate.matches("^[0-9]+(k|m)$")) {
                return false;
            }
            int value = Integer.parseInt(bitrate.replaceAll("[^0-9]", ""));
            return value >= 100 && value <= 50000;
        }
    }
    
    // ====== 원칙 3: 최소 권한 원칙 ======
    
    @Configuration
    public class DatabaseSecurityConfig {
        
        // DB 계정별 권한 설정 (운영)
        /*
        애플리케이션 계정 (app_user):
        - 권한: SELECT, INSERT, UPDATE (특정 테이블만)
        - 대상: users, orders, products 테이블
        - 제한: admin_users, audit_logs 접근 불가
        
        SQL: GRANT SELECT, INSERT, UPDATE ON schema1.users TO 'app_user'@'localhost';
        SQL: GRANT SELECT, INSERT, UPDATE ON schema1.orders TO 'app_user'@'localhost';
        SQL: REVOKE DELETE ON *.* FROM 'app_user'@'localhost';
        
        관리자 계정 (admin_user):
        - 권한: 전체 권한
        - 사용: DBA만 사용
        - 제한: 애플리케이션에서 사용하지 않음
        */
        
        // 권한 분리 전략
        public enum DatabaseRole {
            APP_READ_ONLY("SELECT"),           // 읽기 전용
            APP_WRITE("SELECT, INSERT"),       // 읽기 + 쓰기
            APP_DELETE("SELECT, INSERT, UPDATE, DELETE"),  // 전체 (주의!)
            ADMIN("ALL");                      // 관리자
        }
    }
    
    // ====== 원칙 4: 에러 메시지 숨김 ======
    
    @RestControllerAdvice
    public class GlobalExceptionHandler {
        
        @ExceptionHandler(DataAccessException.class)
        public ResponseEntity<?> handleDatabaseError(DataAccessException ex) {
            // ❌ 나쁜 예
            // return ResponseEntity.status(500).body(ex.getMessage());
            
            // ✅ 좋은 예: 에러 메시지 숨김
            log.error("Database error", ex);
            return ResponseEntity.status(500)
                .body("An error occurred while processing your request");
        }
        
        @ExceptionHandler(Exception.class)
        public ResponseEntity<?> handleException(Exception ex) {
            // 스택 트레이스 로깅 (서버만)
            log.error("Unexpected error", ex);
            
            // 사용자에게는 일반 메시지
            return ResponseEntity.status(500)
                .body("Internal server error");
        }
    }
    
    // ====== 원칙 5: 다층 방어 (Defense in Depth) ======
    
    @Service
    public class SecureUserService {
        
        public List<User> searchUsers(String searchTerm) {
            // 레이어 1: 입력 검증
            if (!inputValidator.isValidSearchTerm(searchTerm)) {
                log.warn("Invalid search term: {}", searchTerm);
                return Collections.emptyList();
            }
            
            // 레이어 2: 길이 제한
            if (searchTerm.length() > 50) {
                throw new IllegalArgumentException("Search term too long");
            }
            
            // 레이어 3: 쿼리 빌더 (파라미터 바인딩)
            Query query = new Query();
            query.addCriteria(Criteria.where("name")
                .regex(".*" + Pattern.quote(searchTerm) + ".*", "i"));
            
            // 레이어 4: 결과 검증 및 제한
            List<User> results = mongoTemplate.find(query, User.class);
            
            // 레이어 5: 응답 제한 (최대 100개)
            return results.stream()
                .limit(100)
                .collect(Collectors.toList());
        }
    }
    
    // ====== 원칙 6: ORM/ODM 올바른 사용 ======
    
    @Repository
    public interface OrderRepository extends JpaRepository<Order, Long> {
        
        // ✅ 권장 패턴 1: 메서드명 쿼리
        List<Order> findByStatusAndCreatedAtAfter(String status, LocalDateTime date);
        
        // ✅ 권장 패턴 2: @Query + 파라미터
        @Query("SELECT o FROM Order o WHERE o.customer.id = :customerId " +
               "AND o.status = :status ORDER BY o.createdAt DESC")
        Page<Order> findCustomerOrders(
            @Param("customerId") Long customerId,
            @Param("status") String status,
            Pageable pageable
        );
        
        // ✅ 권장 패턴 3: QueryDSL (복잡한 쿼리)
        // (별도의 QueryDslPredicateExecutor 인터페이스 상속 필요)
    }
    
    // ====== 원칙 7: 로깅 및 모니터링 ======
    
    @Aspect
    public class DatabaseQueryAudit {
        
        @Around("execution(* org.springframework.jdbc.core.JdbcTemplate.*(..))")
        public Object logQueries(ProceedingJoinPoint joinPoint) throws Throwable {
            String methodName = joinPoint.getSignature().getName();
            long startTime = System.currentTimeMillis();
            
            try {
                Object result = joinPoint.proceed();
                long duration = System.currentTimeMillis() - startTime;
                
                if (duration > 1000) {
                    log.warn("Slow query: {} ms for {}", duration, methodName);
                }
                
                return result;
            } catch (Exception e) {
                log.error("Query execution failed: {}", methodName, e);
                throw e;
            }
        }
    }
}

// ====== Entity 정의 ======

@Entity
@Table(name = "users")
@Data
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, unique = true, length = 50)
    private String username;
    
    @Column(nullable = false, unique = true, length = 100)
    private String email;
    
    @Column(nullable = false, length = 100)
    private String name;
    
    @Column(nullable = false)
    private String passwordHash;
    
    @Column(nullable = false)
    private LocalDateTime createdAt;
}
```

## 🔬 방어 원칙의 내부 동작

### 1. PreparedStatement의 방어 메커니즘

```
일반 SQL 실행 (취약):
┌─────────────────────────────┐
│ SQL 문자열: "SELECT * FROM  │
│   users WHERE id = '1' OR   │
│   '1'='1'"                  │
└──────────┬──────────────────┘
           │
           ↓
┌─────────────────────────────┐
│ SQL Parser                  │
│ - 전체 문자열을 파싱        │
│ - OR '1'='1' 조건 감지      │
│ - 예상과 다른 쿼리 계획 생성│
└──────────┬──────────────────┘
           │
           ↓
┌─────────────────────────────┐
│ 결과: 모든 행 반환 (공격 성공)
└─────────────────────────────┘

PreparedStatement 사용 (안전):
┌─────────────────────────────┐
│ SQL 구조: "SELECT * FROM    │
│   users WHERE id = ?"       │
└──────────┬──────────────────┘
           │
           ↓
┌─────────────────────────────┐
│ SQL Parser (쿼리 계획 생성)  │
│ - "?" 자리에 데이터 들어올  │
│   것을 미리 파악             │
│ - 쿼리 계획 고정            │
└──────────┬──────────────────┘
           │
           ↓
┌─────────────────────────────┐
│ 데이터 바인딩: id = '1' OR '1'='1'
│ (문자열 값 그대로, 메타문자 해석 안 함)
└──────────┬──────────────────┘
           │
           ↓
┌─────────────────────────────┐
│ 결과: id가 정확히 "1' OR '1'='1'"인
│ 행 검색 (없으므로 공집합)
└─────────────────────────────┘
```

### 2. 화이트리스트 vs 블랙리스트

```
블랙리스트 방식 (위험):
┌────────────────────────────────────────┐
│ 금지 문자: ' ; -- /* */ UNION SELECT   │
│                                        │
│ 입력: "admin' UNION /*comment*/ SELECT"
│ 결과: UNION은 차단되지만 SELECT는?     │
│ 결과: /*comment*/는 따옴표 외 문법?    │
│                                        │
│ → 우회 가능한 공격 방식 항상 존재      │
└────────────────────────────────────────┘

화이트리스트 방식 (안전):
┌────────────────────────────────────────┐
│ 허용 문자: [a-zA-Z0-9_]만             │
│                                        │
│ 입력: "admin123"                       │
│ 결과: 모두 허용된 문자 → 통과          │
│                                        │
│ 입력: "admin' OR '1'='1"               │
│ 결과: ' (따옴표) 문자는 미허용 → 차단   │
│                                        │
│ → 우회 불가능 (정의된 문자만 가능)     │
└────────────────────────────────────────┘
```

### 3. 최소 권한 원칙의 효과

```
권한 분리 없음 (피해 확대):
공격자가 SQL Injection 성공
     ↓
애플리케이션 DB 계정 = DBA 권한
     ↓
모든 테이블 접근 가능
     ↓
admin_users (관리자), audit_logs (감사), secrets (보안키) 등 모두 탈취
     ↓
피해: 전체 시스템 장악

권한 분리 (피해 제한):
공격자가 SQL Injection 성공
     ↓
애플리케이션 DB 계정 = 제한된 권한 (users, orders 테이블만)
     ↓
admin_users, audit_logs, secrets 접근 불가
     ↓
탈취 가능 데이터: users, orders 정보만
     ↓
피해: 제한적 (다른 보안 계층으로 추가 방어)
```

## 📌 핵심 정리

### 방어 원칙 7가지

1. **파라미터 바인딩**: SQL 구조와 데이터 완전 분리
   - PreparedStatement, ORM 파라미터 메서드
   - 모든 계층에서 일관되게 적용

2. **입력 검증**: 화이트리스트 기반
   - 허용된 문자/패턴만 통과
   - 역할별 검증 규칙

3. **최소 권한 원칙**: DB 계정 권한 제한
   - 애플리케이션 계정 = SELECT, INSERT만
   - DELETE, DROP 권한 제거

4. **에러 메시지 숨김**: 시스템 정보 유출 방지
   - 사용자: 일반 메시지
   - 로그: 상세 정보

5. **다층 방어 (Defense in Depth)**: 여러 계층에서 검증
   - Controller 검증 → Service 검증 → Repository 검증
   - 한 층이 뚫려도 다른 층이 보호

6. **ORM/ODM 올바른 사용**: 프레임워크 기능 활용
   - 메서드명 쿼리
   - Query 빌더
   - Criteria/QueryDSL API

7. **로깅 및 모니터링**: 공격 탐지 및 분석
   - 느린 쿼리 감지
   - 의심 패턴 로깅
   - 감사(Audit) 기록

## 🤔 생각해볼 문제 (+ 해설)

### Q1: 모든 입력에 화이트리스트를 적용할 수 있는가?

**A**: 아니다. 자유로운 텍스트 필드는 화이트리스트가 과도함.

```java
// ❌ 너무 제한적
// 블로그 글 내용: [a-zA-Z0-9]만 허용 → 사용 불가능

// ✅ 역할별 최적화
// 1. 사용자명 (username): [a-zA-Z0-9_]{3,20} (엄격)
// 2. 블로그 제목: [a-zA-Z0-9\s._-]{1,100} (덜 엄격)
// 3. 블로그 본문: HTML 새니타이제이션 (유연)
// 4. 파일명: [a-zA-Z0-9._-]{1,255} + Path.resolve() (안전성 중심)
```

**권장**: 역할별로 검증 수준 결정

---

### Q2: 정규식(Regex)만으로 충분한가?

**A**: 아니다. 정규식은 포맷 검증이고, 로직 검증은 별개.

```java
// 정규식: 포맷만 검증
email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}$")

// 하지만:
// - 이메일 길이 제한 없음 → DoS 공격 (메일 서버 스팸 등)
// - 실제 존재하는 이메일인지 확인 안 함
// - 사용자가 소유한 이메일인지 확인 안 함

// 추가 검증 필요:
if (email.length() > 254) {  // RFC 5321
    return false;
}

// 이메일 확인: 확인 메일 발송 및 검증 필요
sendVerificationEmail(email);
```

**결론**: 정규식 + 추가 검증 필수

---

### Q3: ORM을 사용하면 항상 안전한가?

**A**: 아니다. ORM도 잘못 사용하면 위험.

```java
// ❌ ORM도 문자열 연결하면 취약
String jpql = "SELECT u FROM User u WHERE u.name = '" + userInput + "'";
Query query = entityManager.createQuery(jpql);

// ✅ ORM의 올바른 사용
@Query("SELECT u FROM User u WHERE u.name = :name")
List<User> findByName(@Param("name") String name);

// 또는:
List<User> findByName(String name);  // 메서드명 쿼리

// 또는:
CriteriaBuilder cb = entityManager.getCriteriaBuilder();
CriteriaQuery<User> cq = cb.createQuery(User.class);
Root<User> user = cq.from(User.class);
cq.where(cb.equal(user.get("name"), userInput));
```

**결론**: ORM 프레임워크의 보안 기능을 반드시 사용

---

<div align="center">

**[⬅️ 이전: LDAP/XML/NoSQL 인젝션](./05-ldap-xml-nosql-injection.md)** | **[홈으로 🏠](../README.md)** | **[다음: 실전 취약점 재현 ➡️](./07-lab-sqli-reproduction.md)**

</div>
