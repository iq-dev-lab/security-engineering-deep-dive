# LDAP/XML/NoSQL 인젝션: 다양한 벡터에서의 구조적 공격

---

## 🎯 핵심 질문

LDAP, XML, NoSQL도 인젝션에 취약한가? MongoDB의 `$where` 연산자는 왜 위험한가? XXE(XML External Entity) 공격으로 서버 파일을 어떻게 읽을 수 있는가? 각 벡터별 방어 전략의 차이는 무엇인가?

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

**다양한 프로토콜/형식의 인젝션**: SQL만큼 위험하지만, 더 많은 개발자가 LDAP, XML, NoSQL의 보안을 간과.

2019년 XXE 데이 (Acunetix 보안 리포트): 전체 웹사이트의 20%가 XXE 취약점 보유. SOAP/XML 기반 서비스에서 `/etc/passwd` 읽기, 내부 네트워크 스캔(SSRF) 가능.

2020년 MongoDB 랜섬웨어: 설정 오류로 NoSQL 데이터베이스 인젝션 가능. 공격자가 `db.collection.find({ $where: "true; delete(this); " })` 로 모든 문서 삭제 후 복구 비용 청구.

한국 금융사 LDAP 인젝션: 사용자 인증 시 LDAP 필터 생성 단계에서 검증 오류. 공격자가 `*)(uid=*))(&(uid=*` 로 인증 우회.

한국 전자상거래 업체 XML 인젝션: API가 XML 기반 요청을 수용. XXE로 내부 서비스 포트 스캔, RCE 벡터 발견.

**실무 위험성**:
- LDAP: 인증 시스템 우회 (Active Directory, OpenLDAP)
- XML: 파일 읽기, SSRF, DoS (Billion Laughs)
- NoSQL: 데이터 조회/변조, 전체 DB 삭제
- 데이터 수집: 감시 대상 확대 (LDAP, LDAP injection)

## 😱 취약한 코드 (Before — 원리를 모를 때의 구현)

```java
// [위험] LDAP, XML, NoSQL에서 검증 없이 입력 사용
@Service
public class VulnerableAuthService {
    
    // ========== LDAP Injection ==========
    
    @Autowired
    private LdapTemplate ldapTemplate;
    
    // 1. LDAP 필터 문자열 연결 (취약)
    public List<String> ldapLogin(String username, String password) {
        // 공격자 입력: username = "*"
        // 최종 필터: (&(uid=*)(userPassword=password))
        // 결과: uid가 뭐든 상관없이 모든 사용자 반환
        
        String filter = "(&(uid=" + username + ")(userPassword=" + password + "))";
        
        List<String> results = ldapTemplate.search(
            "", 
            filter,
            new AttributesMapper<String>() {
                @Override
                public String mapFromAttributes(Attributes attrs) throws NamingException {
                    return (String) attrs.get("uid").get();
                }
            }
        );
        
        return results;
    }
    
    // 2. LDAP 필터 연결 (또 다른 취약 패턴)
    public boolean ldapAuthenticate(String username, String password) {
        // 공격자 입력: username = "admin*", password = "*"
        // 최종 필터: (|(uid=admin*)(userPassword=*))
        // 결과: 모든 사용자 인증 성공
        
        String filter = "(|(uid=" + username + ")(userPassword=" + password + "))";
        
        try {
            List<String> results = ldapTemplate.search("", filter);
            return !results.isEmpty();
        } catch (Exception e) {
            return false;
        }
    }
    
    // ========== XML Injection (XXE) ==========
    
    // 3. XML 파싱 (XXE 취약)
    public User parseUserXml(String xmlContent) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // [위험] 모든 기능 활성화 (XXE 공격 취약)
        
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xmlContent)));
        
        Element root = doc.getDocumentElement();
        String username = root.getElementsByTagName("username").item(0).getTextContent();
        String email = root.getElementsByTagName("email").item(0).getTextContent();
        
        return new User(username, email);
    }
    
    // 4. SOAP 메시지 파싱 (XXE 취약)
    @PostMapping("/soap-login")
    public ResponseEntity<?> soapLogin(@RequestBody String soapMessage) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        
        // 사용자가 제공한 SOAP 메시지 (XXE 공격 가능)
        Document doc = builder.parse(new InputSource(new StringReader(soapMessage)));
        
        // ... 처리
        return ResponseEntity.ok("OK");
    }
    
    // ========== NoSQL Injection (MongoDB) ==========
    
    // 5. MongoDB 쿼리 문자열 연결 (취약)
    public List<Document> mongoFindUsers(String name) {
        MongoCollection<Document> collection = getCollection("users");
        
        // 공격자 입력: name = "{ $ne: null }"
        // 최종 쿼리: { name: { $ne: null } }
        // 결과: 모든 사용자 반환
        
        Document query = Document.parse("{ name: \"" + name + "\" }");
        List<Document> results = new ArrayList<>();
        
        collection.find(query).into(results);
        return results;
    }
    
    // 6. MongoDB 동적 쿼리 ($where 사용, 취약)
    public List<Document> mongoCustomQuery(String condition) {
        MongoCollection<Document> collection = getCollection("users");
        
        // [매우 위험] $where는 JavaScript 실행
        // 공격자 입력: condition = "true; db.users.deleteMany({}); return true"
        // 결과: 모든 사용자 문서 삭제!
        
        Document query = new Document("$where", "function() { return " + condition + "; }");
        
        List<Document> results = new ArrayList<>();
        collection.find(query).into(results);
        return results;
    }
    
    // 7. MongoDB 집계 파이프라인 (취약)
    public List<Document> mongoAggregate(String matchStage) {
        MongoCollection<Document> collection = getCollection("users");
        
        // 공격자 입력: matchStage 에 조작된 필터
        Document stage = Document.parse("{ $match: " + matchStage + " }");
        
        List<Document> results = new ArrayList<>();
        collection.aggregate(Arrays.asList(stage)).into(results);
        return results;
    }
}
```

### 공격 페이로드 사례:

```ldap
# LDAP Injection
# 기본 필터: (&(uid=username)(userPassword=password))

# 1. 인증 우회 (username이 uid 조건 무시)
username: *)(|(uid=*
password: anything

# 최종 필터: (&(uid=*)(|(uid=*)(userPassword=anything))
# 결과: 항상 참

# 2. 필터 닫기로 인증 우회
username: admin*
password: *

# 필터: (&(uid=admin*)(userPassword=*))
# wildcard로 모든 사용자 매칭
```

```xml
<!-- XXE 공격 -->

<!-- 1. 파일 읽기 (LFI) -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<login>
  <username>&xxe;</username>
  <password>anything</password>
</login>

<!-- 응답: /etc/passwd 파일 내용이 에러 메시지에 포함 -->

<!-- 2. 내부 네트워크 스캔 (SSRF) -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://192.168.1.100:8080/">]>
<request>
  <scan>&xxe;</scan>
</request>

<!-- 응답 시간으로 내부 서비스 존재 여부 판별 -->

<!-- 3. Billion Laughs (DoS) -->
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!-- 반복... -->
]>
<lol>&lol3;</lol>

<!-- 메모리 폭발로 서비스 중단 -->
```

```javascript
// MongoDB Injection

// 1. 기본 NoSQL Injection
// 쿼리: { name: "input" }
input = '{ $ne: null }'  // name: { $ne: null } → 모든 문서

// 2. $where로 JavaScript 실행
// 쿼리: { $where: "function() { return condition; }" }
condition = "true; db.users.deleteMany({}); return true"
// 결과: 모든 사용자 문서 삭제

// 3. JavaScript 객체 주입
// 쿼리: db.users.find({ name: ObjectId("...") })
// 공격: name = "'; return true; //"
// 최종: { name: ''; return true; //' }  → 모든 문서 반환

// 4. 집계 파이프라인 주입
// 쿼리: [{ $match: filter }]
filter = "{ $where: \"true; malicious(); return true\" }"
```

## ✨ 방어 코드 (After — 공격 원리를 알고 설계한 구현)

```java
// [방어] LDAP, XML, NoSQL에서 안전한 방어 패턴
@Service
public class SecureAuthService {
    
    // ========== LDAP - 안전한 필터 생성 ==========
    
    @Autowired
    private LdapTemplate ldapTemplate;
    
    // 1. Spring의 LdapQueryBuilder 사용 (권장)
    public List<String> ldapLoginSafe(String username, String password) {
        // LdapQueryBuilder는 자동으로 특수문자 이스케이프
        LdapQuery query = query()
            .where("uid").is(username)  // 파라미터 바인딩
            .and("userPassword").is(password);
        
        List<String> results = ldapTemplate.search(
            query,
            new AttributesMapper<String>() {
                @Override
                public String mapFromAttributes(Attributes attrs) throws NamingException {
                    return (String) attrs.get("uid").get();
                }
            }
        );
        
        return results;
    }
    
    // 2. LDAP 특수문자 이스케이프 (필요시 수동)
    public boolean ldapAuthenticateSafe(String username, String password) {
        // LDAP 특수문자: * ( ) \ NUL
        String escapedUsername = escapeLdapFilter(username);
        String escapedPassword = escapeLdapFilter(password);
        
        LdapQuery query = query()
            .where("uid").is(escapedUsername)
            .and("userPassword").is(escapedPassword);
        
        try {
            List<String> results = ldapTemplate.search(query);
            return !results.isEmpty();
        } catch (Exception e) {
            log.error("LDAP authentication error", e);
            return false;
        }
    }
    
    // LDAP 필터 이스케이프
    private String escapeLdapFilter(String input) {
        if (input == null) return null;
        
        return input
            .replace("\\", "\\5c")
            .replace("*", "\\2a")
            .replace("(", "\\28")
            .replace(")", "\\29")
            .replace("\0", "\\00");
    }
    
    // ========== XML - XXE 방지 ==========
    
    // 3. 안전한 XML 파싱 (XXE 비활성화)
    public User parseUserXmlSafe(String xmlContent) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        
        // XXE 공격 방지
        try {
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);
        } catch (ParserConfigurationException e) {
            throw new RuntimeException("Parser configuration error", e);
        }
        
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xmlContent)));
        
        Element root = doc.getDocumentElement();
        String username = root.getElementsByTagName("username").item(0).getTextContent();
        String email = root.getElementsByTagName("email").item(0).getTextContent();
        
        return new User(username, email);
    }
    
    // 4. OWASP XXE 방지 유틸리티
    private DocumentBuilderFactory buildSecureDocumentBuilderFactory() throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        
        // 모든 DTD 비활성화
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        
        // 외부 엔티티 비활성화
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        
        // 외부 DTD 비활성화
        dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        
        // XInclude 비활성화
        dbf.setXIncludeAware(false);
        
        // 엔티티 참조 확장 비활성화
        dbf.setExpandEntityReferences(false);
        
        return dbf;
    }
    
    // 5. JSON 사용으로 XML 회피 (권장)
    @PostMapping("/login-json")
    public ResponseEntity<?> jsonLogin(@RequestBody LoginRequest request) {
        // JSON은 DTD나 엔티티 선언 불가능
        // XML 대신 JSON 사용 (XXE 방지)
        
        return ResponseEntity.ok("Authenticated");
    }
    
    @Data
    public static class LoginRequest {
        private String username;
        private String password;
    }
    
    // ========== MongoDB - NoSQL Injection 방지 ==========
    
    @Autowired
    private MongoTemplate mongoTemplate;
    
    // 6. MongoDB 타입 안전 쿼리 (권장)
    public List<User> mongoFindUsersSafe(String name) {
        // Query 빌더 사용 (자동 이스케이프)
        Query query = new Query();
        query.addCriteria(Criteria.where("name").is(name));
        
        return mongoTemplate.find(query, User.class);
    }
    
    // 7. MongoDB 집계 파이프라인 (안전)
    public List<Document> mongoAggregateSafe(String nameFilter) {
        MongoCollection<Document> collection = mongoTemplate.getCollection("users");
        
        // Criteria 빌더로 필터 생성 (파라미터 바인딩)
        Document matchStage = new Document("$match", 
            new Document("name", new Document("$regex", "^" + Pattern.quote(nameFilter) + ".*")));
        
        List<Document> results = new ArrayList<>();
        collection.aggregate(Arrays.asList(matchStage)).into(results);
        return results;
    }
    
    // 8. $where 사용 금지 (JavaScript 실행 불가)
    // ❌ 절대 금지:
    // db.users.find({ $where: "function() { return condition; }" })
    
    // ✅ 대신 사용:
    // db.users.find({ status: "active" })
    
    // 9. MongoDB 입력 검증
    public List<User> mongoFindWithValidation(String username) {
        // 입력 검증: 알파벳, 숫자, 언더스코어만 허용
        if (!username.matches("^[a-zA-Z0-9_]{1,50}$")) {
            throw new IllegalArgumentException("Invalid username");
        }
        
        Query query = new Query();
        query.addCriteria(Criteria.where("username").is(username));
        
        return mongoTemplate.find(query, User.class);
    }
    
    // 10. MongoDB 에러 처리
    public List<User> mongoSearchWithErrorHandling(String searchTerm) {
        try {
            Query query = new Query();
            query.addCriteria(Criteria.where("email").regex(".*" + Pattern.quote(searchTerm) + ".*", "i"));
            
            return mongoTemplate.find(query, User.class);
        } catch (MongoException e) {
            log.error("MongoDB error", e);
            // 에러 메시지 숨김
            return Collections.emptyList();
        }
    }
}

// Entity 정의
@Data
@Document(collection = "users")
public class User {
    @Id
    private String id;
    private String username;
    private String email;
}
```

### 의존성 추가 (pom.xml):

```xml
<!-- LDAP -->
<dependency>
    <groupId>org.springframework.ldap</groupId>
    <artifactId>spring-ldap-core</artifactId>
    <version>2.4.1</version>
</dependency>

<!-- MongoDB -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-mongodb</artifactId>
    <version>3.0.0</version>
</dependency>

<!-- XML 보안 -->
<dependency>
    <groupId>xerces</groupId>
    <artifactId>xercesImpl</artifactId>
    <version>2.12.2</version>
</dependency>
```

## 🔬 공격 원리 분석 (공격자 관점의 내부 동작)

### 1. LDAP 필터 인젝션

```
LDAP 필터 구문:
(&(uid=value)(userPassword=value))  → AND 연산
(|(uid=value)(userPassword=value))  → OR 연산
(!(uid=value))                       → NOT 연산

취약한 코드:
String filter = "(&(uid=" + username + ")(userPassword=" + password + "))";

공격 입력:
username = "*" → (&(uid=*)(userPassword=password))
→ uid가 뭐든 상관없이 모든 사용자 매칭

username = "admin*" → (&(uid=admin*)(userPassword=password))
→ uid가 "admin"으로 시작하는 모든 사용자

username = "*)(|(uid=*" → (&(uid=*)(|(uid=*)(userPassword=password))
→ OR 연산으로 인증 우회

방어:
LdapQueryBuilder.query().where("uid").is(username)
→ 특수문자 자동 이스케이프
```

### 2. XXE (XML External Entity) 공격

```xml
공격 메커니즘:
1. DOCTYPE 선언으로 외부 엔티티 정의
2. 엔티티 참조로 외부 리소스 로드
3. 에러 메시지 또는 응답에서 파일 내용 추출

예시:
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<login>
  <username>&xxe;</username>
</login>

파서 처리:
1. &xxe; 참조 발견
2. SYSTEM "file:///etc/passwd" 실행
3. /etc/passwd 파일 로드
4. 에러 메시지에 파일 내용 포함

결과: /etc/passwd 전체 내용 유출

SSRF 벡터:
<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/admin">

내부 포트 스캔:
응답 시간으로 서비스 존재 판별
에러 메시지로 서버 정보 수집
```

### 3. MongoDB NoSQL Injection

```javascript
// 기본 쿼리
db.users.find({ name: "input" })

// SQL Injection과 유사한 공격
input = '{ $ne: null }'
→ db.users.find({ name: { $ne: null } })
→ name이 null이 아닌 모든 문서 반환

// $where로 JavaScript 실행
db.users.find({ $where: "function() { return condition; }" })

// 공격:
condition = "true; db.users.deleteMany({}); return true"
→ 모든 문서 삭제!

// 더 교묘한 공격:
condition = "this.password == 'admin123' || true"
→ 모든 사용자 반환 (인증 우회)

// JavaScript 프로토타입 오염
condition = "this.hasOwnProperty('password') && this.password == 'x' || 1==1"
→ 논리 우회
```

## 💻 실전 실험 (취약점 재현 → 공격 → 방어 검증)

### 실습 1: LDAP Injection

```bash
# 1. LDAP 서버 설정 (Apache Directory Studio)
docker run -d --name ldap-server \
  -p 10389:10389 \
  apacheds:latest

# 2. LDAP 테스트 데이터 설정
# uid=admin,dc=example,dc=com / password=admin123

# 3. 취약한 엔드포인트 테스트
curl -X POST "http://localhost:8080/api/ldap/login" \
  -d "username=*&password=anything"

# 응답: 모든 사용자 인증 성공

# 4. 특정 사용자 필터
curl -X POST "http://localhost:8080/api/ldap/login" \
  -d "username=admin*&password=*"

# 응답: admin 계정 로그인 (비밀번호 우회)
```

### 실습 2: XXE 공격

```bash
# 1. XXE 취약한 API
curl -X POST "http://localhost:8080/api/users/parse" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<login>
  <username>&xxe;</username>
  <password>anything</password>
</login>'

# 응답: /etc/passwd 파일 내용이 에러 메시지에 포함

# 2. SSRF로 내부 서비스 스캔
curl -X POST "http://localhost:8080/api/users/parse" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:8080/">]>
<login>
  <username>&xxe;</username>
</login>'

# 응답 시간으로 내부 서비스 존재 여부 판별
```

### 실습 3: MongoDB Injection

```bash
# 1. MongoDB 환경 구성
docker run -d --name mongo \
  -p 27017:27017 \
  mongo:latest

# 2. 테스트 데이터
mongosh << 'EOF'
db.users.insertMany([
  { name: "admin", password: "secret123" },
  { name: "user1", password: "pass456" }
])
EOF

# 3. NoSQL Injection 테스트
curl -X GET "http://localhost:8080/api/mongo/find" \
  -G --data-urlencode 'name={ $ne: null }'

# 응답: 모든 사용자 반환

# 4. $where로 모든 데이터 삭제 (시뮬레이션)
# 실제로는 매우 위험하므로 로그만 확인
curl -X POST "http://localhost:8080/api/mongo/query" \
  -d 'condition=true; db.users.deleteMany({}); return true'
```

### 실습 4: 방어 코드 검증

```bash
# 1. 안전한 버전 배포
git checkout secure-branch

# 2. 같은 공격 시도 (모두 차단)
curl -X POST "http://localhost:8080/api/ldap/login" \
  -d "username=*&password=anything"

# 응답: "User not found" (특수문자 이스케이프로 "*" 자체를 username으로 검색)

# 3. JSON 사용으로 XXE 완전 방지
curl -X POST "http://localhost:8080/api/users/login-json" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"anything"}'

# 응답: JSON이므로 XXE 불가능

# 4. MongoDB 안전 쿼리
curl -X GET "http://localhost:8080/api/mongo/find-safe" \
  -G --data-urlencode 'name={ $ne: null }'

# 응답: 정규식으로 처리되어 안전 (특수문자 이스케이프)
```

## 📊 공격 성공 조건 vs 방어 성공 조건 비교

| 항목 | 공격 성공 조건 | 방어 성공 조건 |
|------|----------------|----------------|
| **LDAP 필터** | 문자열 연결 | LdapQueryBuilder 또는 이스케이프 |
| **XML 파싱** | DTD/엔티티 활성화 | DocumentBuilderFactory 설정 |
| **NoSQL 쿼리** | 문자열 연결 또는 $where | Query 빌더 + 입력 검증 |
| **입력 검증** | 최소 검증 | 화이트리스트 또는 정규식 |
| **에러 메시지** | 상세 정보 노출 | 일반화된 메시지 |
| **특수문자** | 이스케이프 미처리 | 자동 이스케이프 |
| **프로토콜** | XML, LDAP 필터 | JSON 사용 권장 |

## ⚖️ 트레이드오프 (보안 강화 vs 사용성/성능)

### 1. XML vs JSON (보안 vs 호환성)

**XML (위험)**:
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<request><data>&xxe;</data></request>

<!-- 보안 위험: XXE, Billion Laughs DoS -->
<!-- 호환성: SOAP, 기존 시스템 -->
```

**JSON (안전)**:
```json
{"request": {"data": "value"}}

<!-- 보안: DTD/엔티티 불가능 -->
<!-- 호환성: RESTful API, 현대적 -->
```

**권장**: 새로운 프로젝트는 JSON 사용, 기존 XML 시스템은 XXE 방지 필수

### 2. MongoDB 유연성 vs 보안

**유연한 $where (위험)**:
```javascript
db.users.find({ $where: "function() { return " + userCondition + "; }" })

// 사용자가 복잡한 로직 표현 가능
// 보안: 매우 낮음
```

**제한된 쿼리 (안전)**:
```javascript
db.users.find({ status: userStatus, role: userRole })

// 미리 정의된 필드만 사용
// 보안: 높음
// 기능: 제한적
```

**권장**: 대부분의 경우 제한된 쿼리로 충분, $where 제거

## 📌 핵심 정리

1. **LDAP Injection**: LdapQueryBuilder 또는 특수문자 이스케이프 필수

2. **XXE**: DocumentBuilderFactory에서 DTD/엔티티 비활성화

3. **NoSQL Injection**: Query 빌더 사용 + $where 금지 + 입력 검증

4. **프로토콜 선택**: 가능하면 JSON 사용 (XXE 방지)

5. **공통 방어**: 
   - 입력 검증
   - 타입 안전 쿼리 빌더
   - 에러 메시지 숨김
   - 타임아웃 설정

## 🤔 생각해볼 문제 (+ 해설)

### Q1: XML 스키마 검증(XSD)이 XXE를 방지할 수 있는가?

**A**: 아니다. XSD는 DTD와 무관하므로 XXE 방지 불가능.

```xml
<!-- XSD 검증에도 불구하고 XXE 가능 -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<request>
  <data>&xxe;</data>
</request>

<!-- XSD는 element/attribute 구조만 검증 -->
<!-- DTD의 엔티티 정의는 XSD가 볼 수 없음 -->
```

**방어**: DocumentBuilderFactory 설정 필수 (XSD는 부가적)

---

### Q2: MongoDB 맵리듀스는 안전한가?

**A**: 아니다. 맵리듀스도 JavaScript 실행이므로 위험.

```javascript
// 취약한 사용
db.users.mapReduce(
  function() { emit(this.name, 1); },
  function(name, values) { return Array.sum(values); },
  { query: { $where: userInput } }  // 위험!
)

// 안전한 사용
db.users.mapReduce(
  function() { emit(this.name, 1); },
  function(name, values) { return Array.sum(values); },
  { query: { status: "active" } }  // 고정된 필터
)
```

**권장**: 맵리듀스 대신 Aggregation Framework 사용

---

### Q3: LDAP 이스케이프 함수를 직접 구현할 수 있는가?

**A**: 이론적으로는 가능하지만, 권장하지 않음.

```java
// 직접 이스케이프 (위험)
String escaped = input
    .replace("\\", "\\5c")
    .replace("*", "\\2a")
    // ... 모든 특수문자 처리해야 함

// 빠뜨린 문자가 있으면 취약

// 권장: 라이브러리 사용
LdapQuery query = query().where("uid").is(input);
// Spring LDAP가 모든 이스케이프 처리
```

---

<div align="center">

**[⬅️ 이전: 명령어 인젝션](./04-command-injection.md)** | **[홈으로 🏠](../README.md)** | **[다음: 인젝션 방어 원칙 ➡️](./06-injection-defense-principles.md)**

</div>
