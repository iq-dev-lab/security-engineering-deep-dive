# SQL Injection 원리: 데이터베이스 파서 무력화

---

## 🎯 핵심 질문

데이터베이스가 사용자 입력을 어떻게 해석하는가? SQL 문자열 연결이 왜 치명적인가? `' OR '1'='1`이 모든 레코드를 반환하는 내부 메커니즘은 무엇인가?

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

2013년 Adobe 데이터 유출 사건: 1.5억 개 사용자 계정 탈취. SQL Injection으로 고객 데이터베이스에 접근하여 비밀번호, 이메일, 신용카드 정보 추출.

2019년 Capital One 데이터 유출: 7,500만 명의 개인정보 탈취. AWS 웹 애플리케이션 방화벽(WAF) 우회하여 SQL Injection 실행. **복구 비용: 7,000만 달러**.

한국 금융권 2023년 사건: 인터넷 뱅킹 플랫폼의 로그인 기능에서 사용자명 입력 필드에 SQL Injection 가능. 공격자는 `' OR '1'='1`을 입력하여 모든 사용자의 계좌 정보 조회 가능 상태 발견.

**실무 위험성**:
- 인증 우회 (로그인 없이 모든 사용자 접근)
- 데이터 유출 (개인정보, 금융정보, 의료기록)
- 데이터 변조 (계좌 이체 금액 조작, 주문 정보 위조)
- 관리자 권한 탈취
- 데이터베이스 서버 접근권 확보 후 OS 명령 실행

## 😱 취약한 코드 (Before — 원리를 모를 때의 구현)

```java
// [위험] 사용자 입력을 직접 SQL에 연결
@RestController
@RequestMapping("/api/users")
public class UserController {
    
    @Autowired
    private JdbcTemplate jdbcTemplate;
    
    // 1. 기본적인 취약한 패턴
    @GetMapping("/login")
    public ResponseEntity<?> login(@RequestParam String username, 
                                   @RequestParam String password) {
        String query = "SELECT * FROM users WHERE username = '" + username 
                     + "' AND password = '" + password + "'";
        
        List<Map<String, Object>> result = jdbcTemplate.queryForList(query);
        
        if (!result.isEmpty()) {
            return ResponseEntity.ok("Login successful!");
        }
        return ResponseEntity.status(401).body("Invalid credentials");
    }
    
    // 2. UNION을 이용한 데이터 추출
    @GetMapping("/search")
    public ResponseEntity<?> searchUser(@RequestParam String name) {
        // 공격자 입력: ' UNION SELECT table_name FROM information_schema.tables WHERE '1'='1
        String query = "SELECT id, name, email FROM users WHERE name LIKE '%" 
                     + name + "%'";
        
        List<Map<String, Object>> result = jdbcTemplate.queryForList(query);
        return ResponseEntity.ok(result);
    }
    
    // 3. 에러 기반 추출이 가능한 패턴
    @GetMapping("/profile/{userId}")
    public ResponseEntity<?> getUserProfile(@PathVariable String userId) {
        // 공격자 입력: 1' AND extractvalue(1, concat(0x7e, (SELECT password FROM users LIMIT 1))) AND '1'='1
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        
        try {
            List<Map<String, Object>> result = jdbcTemplate.queryForList(query);
            return ResponseEntity.ok(result);
        } catch (DataAccessException e) {
            // 에러 메시지에 데이터가 포함됨
            return ResponseEntity.status(500).body(e.getMessage());
        }
    }
}
```

### 공격 페이로드 사례 (위 코드에 적용 시):

```sql
-- 1. 인증 우회 (login 엔드포인트)
username: admin' --
password: anything

-- 실제 실행되는 쿼리:
-- SELECT * FROM users WHERE username = 'admin' --' AND password = 'anything'
-- SQL 주석(--) 이후 password 조건 무시됨

-- 2. 모든 레코드 반환
username: ' OR '1'='1
password: ' OR '1'='1

-- 실제 실행되는 쿼리:
-- SELECT * FROM users WHERE username = '' OR '1'='1' AND password = '' OR '1'='1'
-- '1'='1'은 항상 참이므로 WHERE 절 무력화

-- 3. UNION을 이용한 스키마 추출 (searchUser 엔드포인트)
name: ' UNION SELECT table_name, 2, 3 FROM information_schema.tables WHERE table_schema='mysql' AND '1'='1

-- 4. 에러 기반 추출 (getUserProfile 엔드포인트)
userId: 1' AND extractvalue(1, concat(0x7e, (SELECT concat(username, ':', password) FROM users LIMIT 1))) AND '1'='1

-- MySQL 에러 출력:
-- XPATH syntax error: '~admin:password123'
```

## ✨ 방어 코드 (After — 공격 원리를 알고 설계한 구현)

```java
// [방어] PreparedStatement를 사용한 파라미터 바인딩
@RestController
@RequestMapping("/api/users")
public class SecurityUserController {
    
    @Autowired
    private JdbcTemplate jdbcTemplate;
    
    @Autowired
    private NamedParameterJdbcTemplate namedParameterJdbcTemplate;
    
    // 1. PreparedStatement로 안전한 로그인
    @GetMapping("/login")
    public ResponseEntity<?> login(@RequestParam String username, 
                                   @RequestParam String password) {
        // PreparedStatement: SQL 구조와 데이터를 분리
        String query = "SELECT * FROM users WHERE username = ? AND password = ?";
        
        List<Map<String, Object>> result = jdbcTemplate.queryForList(
            query, 
            username,  // 첫 번째 ? 에 바인딩
            password   // 두 번째 ? 에 바인딩
        );
        
        if (!result.isEmpty()) {
            return ResponseEntity.ok("Login successful!");
        }
        return ResponseEntity.status(401).body("Invalid credentials");
    }
    
    // 2. Named Parameters로 가독성 향상
    @GetMapping("/search")
    public ResponseEntity<?> searchUser(@RequestParam String name) {
        String query = "SELECT id, name, email FROM users WHERE name LIKE :name";
        
        Map<String, Object> params = new HashMap<>();
        params.put("name", "%" + name + "%");  // LIKE 와일드카드는 Java에서 처리
        
        List<Map<String, Object>> result = namedParameterJdbcTemplate.queryForList(
            query, 
            params
        );
        
        return ResponseEntity.ok(result);
    }
    
    // 3. 에러 메시지 숨김 + PreparedStatement
    @GetMapping("/profile/{userId}")
    public ResponseEntity<?> getUserProfile(@PathVariable String userId) {
        String query = "SELECT id, name, email, role FROM users WHERE id = ?";
        
        try {
            // userId는 SQL 구조 변경 불가능
            List<Map<String, Object>> result = jdbcTemplate.queryForList(query, userId);
            
            if (result.isEmpty()) {
                return ResponseEntity.status(404).body("User not found");
            }
            
            return ResponseEntity.ok(result.get(0));
        } catch (DataAccessException e) {
            // 에러 메시지 로깅만 하고 사용자에게는 일반 메시지 반환
            log.error("Database error occurred", e);
            return ResponseEntity.status(500)
                .body("An error occurred while processing your request");
        }
    }
    
    // 4. RowMapper를 사용한 타입 안전 쿼리
    @GetMapping("/user/{id}")
    public ResponseEntity<User> getUserTypeSafe(@PathVariable Long id) {
        String query = "SELECT id, username, email, created_at FROM users WHERE id = ?";
        
        User user = jdbcTemplate.queryForObject(
            query,
            new RowMapper<User>() {
                @Override
                public User mapRow(ResultSet rs, int rowNum) throws SQLException {
                    return new User(
                        rs.getLong("id"),
                        rs.getString("username"),
                        rs.getString("email"),
                        rs.getTimestamp("created_at").toLocalDateTime()
                    );
                }
            },
            id
        );
        
        return ResponseEntity.ok(user);
    }
    
    // 5. 암호화된 비밀번호로 추가 보안
    @PostMapping("/login-secure")
    public ResponseEntity<?> loginSecure(@RequestBody LoginRequest request) {
        String query = "SELECT id, username, password_hash, salt FROM users WHERE username = ?";
        
        List<Map<String, Object>> results = jdbcTemplate.queryForList(query, request.getUsername());
        
        if (results.isEmpty()) {
            // 존재하지 않는 사용자도 같은 처리 시간 (타이밍 공격 방어)
            return ResponseEntity.status(401).body("Invalid credentials");
        }
        
        Map<String, Object> user = results.get(0);
        String hash = (String) user.get("password_hash");
        String salt = (String) user.get("salt");
        
        // bcrypt 또는 argon2로 비밀번호 검증
        if (passwordEncoder.matches(request.getPassword(), hash)) {
            return ResponseEntity.ok("Login successful!");
        }
        
        return ResponseEntity.status(401).body("Invalid credentials");
    }
}
```

## 🔬 공격 원리 분석 (공격자 관점의 내부 동작)

### 1. SQL 문자열 연결에서 DB 파서가 하는 일

```
입력값: admin' --
SQL 쿼리 구성: SELECT * FROM users WHERE username = 'admin' --' AND password = '...'

데이터베이스 파서의 처리:
1. SELECT * FROM users → 모든 컬럼 선택
2. WHERE username = 'admin' → 'admin' 까지만 문자열로 인식
3. -- → SQL 주석 시작
4. ' AND password = '...' → 주석이므로 무시
5. 최종 의도: WHERE username = 'admin' 만 실행됨

결과: username이 'admin'인 모든 사용자 반환 (비밀번호 조건 무시)
```

### 2. `' OR '1'='1` 이 작동하는 원리

```
입력값: ' OR '1'='1
원본 SQL: SELECT * FROM users WHERE username = '' OR '1'='1' AND password = ''

파서의 해석:
1. WHERE username = '' → 빈 문자열 (거짓)
2. OR '1'='1' → 참
3. AND password = '' → 거짓

논리 연산:
WHERE (username = '') OR ('1'='1') AND (password = '')
WHERE false OR true AND false
WHERE false OR false  (AND가 OR보다 우선순위 높음)
WHERE false           ← 이건 틀렸다! 실제로는:
WHERE (false OR true) AND false = false

실제 대부분 DB의 처리:
WHERE (username = '') OR (('1'='1') AND (password = ''))
WHERE false OR (true AND false)
WHERE false OR false = false

BUT! 공격자가 원하는 것:
WHERE username = '' OR '1'='1
이 경우 OR 이후 모든 행이 선택됨

그러므로 이 공격은:
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = ''
실제로는 두 번째 문자열 경계가 생겨서 실패할 수 있음.

더 효과적인 공격:
SELECT * FROM users WHERE username = 'admin' OR '1'='1' --
여기서 --는 나머지를 주석 처리
```

### 3. UNION SELECT로 information_schema 추출

```
원본 SQL: SELECT id, name FROM users WHERE id = 1

공격 페이로드:
id = 1 UNION SELECT table_name, column_name FROM information_schema.columns --

최종 쿼리:
SELECT id, name FROM users WHERE id = 1
UNION
SELECT table_name, column_name FROM information_schema.columns --

결과: 
- 첫 줄: users 테이블에서 id=1인 행 (컬럼 2개)
- 나머지: information_schema에 있는 모든 테이블명, 컬럼명 (컬럼 2개)

이를 통해 공격자는:
- 데이터베이스 구조 파악
- 숨겨진 테이블/컬럼 발견
- 관리자 테이블 위치 파악
- 후속 공격 계획
```

### 4. 에러 기반 추출 (Error-Based SQLi)

```
MySQL의 extractvalue() 함수를 악용:
extractvalue(1, xpath_expr)

공격 페이로드:
SELECT * FROM users WHERE id = 1' AND extractvalue(1, concat(0x7e, (SELECT password FROM users LIMIT 1))) -- '

동작 원리:
1. (SELECT password FROM users LIMIT 1) → 첫 사용자 비밀번호 조회
2. concat(0x7e, ...) → 비밀번호 앞에 ~ 붙임
3. extractvalue(1, '~password') → XPATH 문법 에러 발생
4. MySQL이 에러 메시지에 유효하지 않은 XPATH 표현식 출력
5. 에러 메시지: XPATH syntax error: '~password123'
6. 공격자가 에러 메시지에서 비밀번호 추출

이 기법의 핵심: 에러 메시지가 데이터를 포함하고, 응용프로그램이 에러를 사용자에게 그대로 반환
```

## 💻 실전 실험 (취약점 재현 → 공격 → 방어 검증)

### 실습 1: 기본 SQL Injection 재현

```bash
# 1. 취약한 Spring Boot 앱 실행
git clone https://github.com/WebGoat/WebGoat.git
cd WebGoat
mvn spring-boot:run

# 2. 로그인 취약점 테스트
# http://localhost:8080/WebGoat/lesson/1/test 에서

# 취약한 엔드포인트에 SQL Injection
curl -X GET "http://localhost:8080/api/users/login" \
  -G --data-urlencode "username=admin' --" \
  --data-urlencode "password=anything"

# 응답: "Login successful!" (비밀번호 검증 무시됨)
```

### 실습 2: UNION SELECT로 정보 추출

```bash
# 테스트 데이터베이스 구성
docker run -d \
  --name vulnerable-db \
  -e MYSQL_ROOT_PASSWORD=root \
  -e MYSQL_DATABASE=testdb \
  mysql:5.7

# 초기 데이터 설정
mysql -h localhost -u root -proot testdb << EOF
CREATE TABLE users (
  id INT PRIMARY KEY,
  username VARCHAR(100),
  password VARCHAR(100),
  email VARCHAR(100),
  role VARCHAR(50)
);

INSERT INTO users VALUES 
(1, 'admin', 'admin123', 'admin@test.com', 'admin'),
(2, 'user1', 'pass123', 'user1@test.com', 'user');

CREATE TABLE admin_credentials (
  id INT PRIMARY KEY,
  secret_key VARCHAR(255),
  api_token VARCHAR(255)
);

INSERT INTO admin_credentials VALUES
(1, 'secret_key_xyz', 'token_abc123');
EOF

# 공격: information_schema에서 모든 테이블 정보 추출
curl -X GET "http://localhost:8080/api/users/search" \
  -G --data-urlencode "name=' UNION SELECT 1, table_name, 3 FROM information_schema.tables WHERE table_schema='testdb' -- "

# 응답에 모든 테이블명 표시
```

### 실습 3: 방어 코드 검증

```bash
# 방어된 버전 배포
# git checkout secure-branch

# 같은 공격 시도
curl -X GET "http://localhost:8080/api/users/login" \
  -G --data-urlencode "username=admin' --" \
  --data-urlencode "password=anything"

# 응답: "Invalid credentials" (공격 차단됨)
# 로그에만 의심 활동 기록

# PreparedStatement 덕분에:
# - username = "admin' --" (전체를 문자열 값으로 취급)
# - 이는 실제 사용자명이 "admin' --"인 경우만 로그인 허용
# - SQL 구조 변경 불가능
```

### 실습 4: 타임 기반 블라인드 SQLi (다음 장)

```bash
# SLEEP을 사용한 시간차 공격 (타이밍 기반 데이터 추출)
# 이는 02-blind-sql-injection.md에서 자세히 다룸

# 취약한 엔드포인트:
curl -X GET "http://localhost:8080/api/users/profile/1" \
  -G --data-urlencode "userId=1' AND IF(1=1, SLEEP(5), 0) -- "

# 응답이 5초 지연됨 → 조건이 참이라는 증거
```

## 📊 공격 성공 조건 vs 방어 성공 조건 비교

| 항목 | 공격 성공 조건 | 방어 성공 조건 |
|------|----------------|----------------|
| **입력 검증** | 최소한의 검증 (길이만 체크) | 화이트리스트 기반 검증 |
| **쿼리 구성** | 문자열 연결 (`+`, `String.format`) | PreparedStatement / 파라미터 바인딩 |
| **에러 처리** | 에러 메시지를 사용자에게 노출 | 에러 메시지 일반화 + 상세 로깅 |
| **DB 권한** | DBA 권한의 계정으로 쿼리 실행 | 최소 권한 계정 (SELECT만 가능) |
| **입력 길이** | 무제한 또는 매우 긴 길이 허용 | 합리적인 길이 제한 |
| **특수문자** | 이스케이프 미처리 | PreparedStatement가 자동 처리 |
| **응답 차이** | 성공/실패 응답이 명확히 구분 | 타이밍, 에러 메시지 동일 |
| **ORM 사용** | 문자열 연결로 쿼리 동적 생성 | ORM 파라미터 메서드 (setParameter 등) |

## ⚖️ 트레이드오프 (보안 강화 vs 사용성/성능)

### 1. 보안 vs 개발 속도

**취약한 방식 (빠름)**:
```java
String query = "SELECT * FROM users WHERE name = '" + name + "'";
```
- 코드 작성: 1분
- 보안: 매우 낮음

**방어 방식 (더 안전)**:
```java
String query = "SELECT * FROM users WHERE name = ?";
List<Map<String, Object>> result = jdbcTemplate.queryForList(query, name);
```
- 코드 작성: 2분
- 보안: 매우 높음
- **대가**: 약간의 추가 학습 곡선, 하지만 필수

### 2. 기능 vs 보안 (LIKE 와일드카드)

**문제**: LIKE는 와일드카드 이스케이프가 필요

```java
// 공격 페이로드: % 또는 _ 를 사용한 정보 유출
// input = "%"  → LIKE '%' (모든 행)

// PreparedStatement 사용:
String query = "SELECT * FROM users WHERE name LIKE ?";
List<Map<String, Object>> result = jdbcTemplate.queryForList(
    query, 
    "%" + userInput + "%"  // 와일드카드는 Java에서 처리
);

// 이 경우 userInput의 % 문자는 LIKE의 와일드카드가 아님
// 예: userInput = "%admin%" → LIKE '%\%admin\%%'로 이스케이프 필요
```

### 3. 성능 vs 보안

**쿼리 최적화 필요시**:
```java
// 보안 + 성능: 인덱스를 활용한 쿼리 계획
String query = "SELECT id, name FROM users WHERE age > ? AND created_at > ? LIMIT ?";
// PreparedStatement + LIMIT + 적절한 인덱스 → 성능 손실 최소화

// 동적 쿼리가 필요한 경우:
// Criteria API / JPA 2.1+ Criteria를 사용
CriteriaBuilder cb = em.getCriteriaBuilder();
CriteriaQuery<User> cq = cb.createQuery(User.class);
Root<User> root = cq.from(User.class);
cq.select(root).where(cb.equal(root.get("username"), username));
// 이 방식은 자동으로 파라미터 바인딩 적용
```

## 📌 핵심 정리

1. **SQL Injection의 근본 원인**: 사용자 입력을 SQL 문자열로 취급하여 DB 파서가 데이터가 아닌 명령어로 해석

2. **PreparedStatement의 원리**: SQL 구조와 데이터를 완전히 분리하여 DB 드라이버 레벨에서 파라미터를 안전하게 바인딩

3. **공격 기법 3가지**:
   - UNION SELECT: 데이터 추출
   - Error-based: 에러 메시지에서 데이터 유출
   - 논리 연산 우회: `' OR '1'='1`로 WHERE 절 무력화

4. **방어 전략**: PreparedStatement + 입력 검증 + 에러 처리 + 최소 권한

5. **Java/Spring에서의 구현**:
   - JdbcTemplate: `queryForList(query, params)`
   - Named Parameters: `namedParameterJdbcTemplate.queryForList(query, paramMap)`
   - JPA: `@Query(value="...", nativeQuery=false)` + `setParameter()`

## 🤔 생각해볼 문제 (+ 해설)

### Q1: PreparedStatement를 사용했는데도 LIKE 와일드카드 주입이 가능한가?

```java
String query = "SELECT * FROM users WHERE name LIKE ?";
String userInput = "%admin%";
List<Map<String, Object>> result = jdbcTemplate.queryForList(query, userInput);
```

**A**: 아니다. PreparedStatement를 사용하면 `%admin%`는 리터럴 문자열로 취급되어 와일드카드로 작동하지 않는다. 

하지만 **응용프로그램에서** 와일드카드를 추가하려면:
```java
String userInput = "admin";
String query = "SELECT * FROM users WHERE name LIKE ?";
// % 문자를 Java에서 추가 (DB에서는 안 함)
result = jdbcTemplate.queryForList(query, "%" + userInput + "%");
```

이 경우 userInput이 "%"를 포함해도 안전하다. (SQL 파서가 아닌 Java 문자열 연결이므로)

---

### Q2: 비밀번호를 해싱하지 않고 평문으로 저장하면, PreparedStatement도 도움이 안 되는가?

**A**: 맞다. PreparedStatement는 SQL Injection만 방어한다. **데이터 저장 보안은 별개의 문제**:

```
PreparedStatement: SQL Injection 방어 ✅
암호화/해싱: 저장된 데이터 보호 ✅
타이밍 공격 방어: 동일한 응답 시간 ✅
```

비밀번호는 반드시:
```java
// bcrypt 사용 (Spring Security)
String hashedPassword = passwordEncoder.encode(rawPassword);
// 저장: hashedPassword만 DB에 저장
// 검증: passwordEncoder.matches(inputPassword, hashedPassword)
```

---

### Q3: `Integer.parseInt(id)`로 검증하면 SQL Injection이 불가능한가?

```java
Integer id = Integer.parseInt(request.getParameter("id"));  // 숫자만 통과
String query = "SELECT * FROM users WHERE id = " + id;      // 문자열 연결
```

**A**: 이 경우 SQL Injection이 불가능하다. 하지만 **안티패턴**:

1. 타입 강제 검증은 매우 제한적 (오직 숫자/UUID 정도만 가능)
2. 문자열 필드는 불가능
3. 여전히 PreparedStatement를 사용하는 것이 최선의 관행
4. 숫자도 PreparedStatement 권장:

```java
// 더 명확하고 일관된 방식
String query = "SELECT * FROM users WHERE id = ?";
List<Map<String, Object>> result = jdbcTemplate.queryForList(query, id);
```

---

<div align="center">

**[홈으로 🏠](../README.md)** | **[다음: Blind SQL Injection ➡️](./02-blind-sql-injection.md)**

</div>
