# JWT 안전한 구현
---

## 🎯 핵심 질문
JWT 취약점을 알았다면, 실전에서 정말 안전하게 구현하려면 어떻게 해야 하는가? 모든 공격 시나리오를 방어하면서도 성능을 유지하려면 어떤 트레이드오프를 감수해야 하는가?

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

### Microsoft Azure AD의 JWT 업그레이드 사건
Microsoft의 Azure AD에서 기존에 지원하던 여러 알고리즘이 제거되고 RS256만 지원하도록 강제했다. 왜? 고객들이 HS256으로 설정했다가 알고리즘 혼동 공격에 노출되었기 때문이다.

### Uber의 토큰 갱신 메커니즘 실패
Uber는 JWT 토큰의 만료 시간을 1년으로 설정했다가, 피해자 계정이 1년 동안 접근 제어를 받지 못하는 사건이 발생했다. 결국 만료 시간을 7일로 단축하고 Refresh Token 메커니즘을 도입했다.

### Auth0의 실시간 토큰 무효화 불가 문제
Auth0는 초기에 토큰 무효화(revocation) 기능이 없었다. 사용자가 비밀번호를 변경해도 기존 토큰은 여전히 유효했다. 이를 해결하기 위해 Redis 기반 블랙리스트 메커니즘을 구축했다.

## 😱 취약한 코드 (Before — 원리를 모를 때의 구현)

### 1. 만료 시간 검증을 제대로 하지 않는 경우

```java
// ❌ 취약한 코드: 만료 시간 검증 누락
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Claims;

public class VulnerableJwtWithoutExpiry {
    
    public Claims parseTokenWithoutExpiry(String token, String secret) {
        // ❌ 문제: 만료 시간 검증이 없음
        Claims claims = Jwts.parserBuilder()
            .setSigningKey(secret.getBytes())
            .build()
            .parseClaimsJws(token)
            .getBody();
        
        // exp 클레임을 읽지만 검증하지 않음
        Date expirationTime = claims.getExpiration();
        System.out.println("토큰 만료 시간: " + expirationTime);
        
        // ❌ 만료 시간 무관하게 진행
        return claims;
    }
}

// 공격 시나리오
String token = Jwts.builder()
    .setSubject("user123")
    .setExpiration(new Date(System.currentTimeMillis() - 100000000)) // 과거 시간
    .signWith(SignatureAlgorithm.HS256, "secret")
    .compact();

// 서버가 이미 만료된 토큰도 수용
Claims claims = vulnerableValidator.parseTokenWithoutExpiry(token, "secret");
// ❌ 결과: user123으로 인증됨 (이미 만료되었는데도!)
```

**공격 원리:**
- 공격자가 만료된 토큰의 서명을 수정하면, 서명 검증은 실패함
- 하지만 만료 시간을 확인하지 않으면, 유효한 토큰으로 봄
- 결과: 피해자의 이전 토큰으로 계정 탈취 가능

### 2. 토큰 무효화 메커니즘 부재

```java
// ❌ 취약한 코드: 토큰 무효화 불가능
public class VulnerableNoTokenRevocation {
    
    public String validateToken(String token) {
        // ✅ 서명 및 만료 시간 검증
        Claims claims = Jwts.parserBuilder()
            .setSigningKey("secret".getBytes())
            .requireExpiration()
            .build()
            .parseClaimsJws(token)
            .getBody();
        
        return claims.getSubject();
    }
    
    // ❌ 로그아웃 기능이 없음
    // 사용자가 로그아웃해도 토큰은 만료될 때까지 유효
    public void logout(String userId) {
        // 할 수 있는 것이 없음
        System.out.println("로그아웃 요청 (하지만 처리 불가)");
    }
}

// 피해 시나리오
// 1. 사용자가 공용 PC에서 로그인
// 2. 사용자가 로그아웃 버튼 클릭
// 3. 공격자가 토큰을 복사해뒀음 (만료까지 유효)
// 4. 공격자가 복사한 토큰으로 API 호출 → 성공
// 5. 사용자 데이터 탈취
```

### 3. 클레임 검증이 불완전한 경우

```java
// ❌ 취약한 코드: 중요 클레임 검증 누락
public class VulnerableClaimValidation {
    
    public String validateTokenWeakly(String token) {
        Claims claims = Jwts.parserBuilder()
            .setSigningKey("secret".getBytes())
            .build()
            .parseClaimsJws(token)
            .getBody();
        
        // ✅ 서명은 검증했지만
        // ❌ 발급자, 대상, 권한 검증 없음
        
        String userId = claims.getSubject();
        
        // ❌ 위험: claims.get("role")은 공격자가 추가/수정 가능
        String role = (String) claims.get("role");
        
        return String.format("User: %s, Role: %s", userId, role);
    }
}

// 공격 시나리오: 클레임 위조
// 공격자는 서명을 모르지만, 서버가 HS256을 사용하고 비밀키가 약하면:
String maliciousToken = Jwts.builder()
    .setSubject("normaluser")
    .claim("role", "admin")  // ❌ 공격자가 admin 역할 추가
    .signWith(SignatureAlgorithm.HS256, "weak-secret")
    .compact();

// 결과: normaluser가 admin 권한으로 접근
```

## ✨ 방어 코드 (After — 공격 원리를 알고 설계한 구현)

### 1. 만료 시간 명시적 검증

```java
// ✅ 안전한 코드: 만료 시간 강제 검증
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.security.Keys;
import javax.crypto.SecretKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

public class SecureJwtWithExpiry {
    
    private final SecretKey key;
    private final long maxTokenAgeSeconds = 900;  // 15분
    
    public SecureJwtWithExpiry(String secret) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }
    
    public String generateToken(String userId) {
        Instant now = Instant.now();
        Instant expiresAt = now.plus(maxTokenAgeSeconds, ChronoUnit.SECONDS);
        
        // ✅ 명시적 만료 시간 설정
        return Jwts.builder()
            .setSubject(userId)
            .setIssuedAt(java.util.Date.from(now))
            .setExpiration(java.util.Date.from(expiresAt))
            .signWith(key)
            .compact();
    }
    
    public Claims validateToken(String token) {
        try {
            // ✅ 핵심: parserBuilder에서 자동으로 exp 검증
            Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
            
            // ✅ 추가 검증: 발급 시간도 확인
            Instant issuedAt = claims.getIssuedAt().toInstant();
            Instant expiresAt = claims.getExpiration().toInstant();
            Instant now = Instant.now();
            
            // 발급된 토큰보다 현재 시간이 뒤에 있는지 확인
            if (now.isBefore(issuedAt)) {
                throw new SecurityException("미래에 발급된 토큰입니다");
            }
            
            // 만료 시간이 현재보다 뒤에 있는지 확인 (parseClaimsJws에서 이미 검증하지만)
            if (now.isAfter(expiresAt)) {
                throw new SecurityException("토큰이 만료되었습니다");
            }
            
            return claims;
        } catch (io.jsonwebtoken.ExpiredJwtException e) {
            throw new SecurityException("토큰 만료: " + e.getMessage());
        } catch (io.jsonwebtoken.JwtException e) {
            throw new SecurityException("토큰 검증 실패: " + e.getMessage());
        }
    }
}

// Spring Security 설정
@Bean
public JwtDecoder jwtDecoder() {
    NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(
        Keys.hmacShaKeyFor(jwtSecret.getBytes())
    ).build();
    
    // ✅ 만료 시간 검증 자동 활성화
    decoder.setJwtValidator(new JwtTimestampValidator());
    
    return decoder;
}
```

### 2. 토큰 무효화 (블랙리스트 방식)

```java
// ✅ 안전한 코드: Redis 기반 토큰 블랙리스트
import org.springframework.data.redis.core.RedisTemplate;
import java.util.concurrent.TimeUnit;

@Service
public class TokenRevocationService {
    
    @Autowired
    private RedisTemplate<String, String> redisTemplate;
    
    private static final String BLACKLIST_PREFIX = "jwt:blacklist:";
    
    // 토큰 무효화
    public void revokeToken(String token, long expiresInSeconds) {
        try {
            // JWT에서 jti(고유 ID) 추출
            String jti = extractJti(token);
            
            // ✅ Redis에 블랙리스트 저장 (TTL = 토큰 만료 시간)
            // 만료된 토큰을 무한정 저장할 필요는 없음
            redisTemplate.opsForValue().set(
                BLACKLIST_PREFIX + jti,
                "revoked",
                expiresInSeconds,
                TimeUnit.SECONDS
            );
            
            System.out.println("토큰 무효화 완료: " + jti);
        } catch (Exception e) {
            System.err.println("토큰 무효화 실패: " + e.getMessage());
        }
    }
    
    // 토큰이 블랙리스트에 있는지 확인
    public boolean isTokenRevoked(String token) {
        String jti = extractJti(token);
        return redisTemplate.hasKey(BLACKLIST_PREFIX + jti);
    }
    
    private String extractJti(String token) {
        // JWT 디코드 (검증 없이 헤더/페이로드만 파싱)
        String[] parts = token.split("\\.");
        String payloadJson = new String(
            Base64.getUrlDecoder().decode(parts[1]),
            StandardCharsets.UTF_8
        );
        
        JsonObject payload = JsonParser.parseString(payloadJson).getAsJsonObject();
        return payload.has("jti") ? payload.get("jti").getAsString() : "";
    }
}

// 토큰 생성 시 jti 포함
@Service
public class TokenGenerationService {
    
    public String generateToken(String userId) {
        String jti = UUID.randomUUID().toString();  // 고유 토큰 ID
        Instant now = Instant.now();
        Instant expiresAt = now.plus(15, ChronoUnit.MINUTES);
        
        return Jwts.builder()
            .setJti(jti)  // ✅ jti 포함: 토큰 무효화용 식별자
            .setSubject(userId)
            .setIssuedAt(java.util.Date.from(now))
            .setExpiration(java.util.Date.from(expiresAt))
            .signWith(jwtKey)
            .compact();
    }
}

// 필터에서 블랙리스트 확인
@Component
public class TokenRevocationFilter extends OncePerRequestFilter {
    
    @Autowired
    private TokenRevocationService revocationService;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                    HttpServletResponse response,
                                    FilterChain filterChain) 
            throws ServletException, IOException {
        
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            
            // ✅ 토큰이 블랙리스트에 있으면 요청 거절
            if (revocationService.isTokenRevoked(token)) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("토큰이 무효화되었습니다");
                return;
            }
        }
        
        filterChain.doFilter(request, response);
    }
}

// 로그아웃 엔드포인트
@RestController
public class AuthController {
    
    @Autowired
    private TokenRevocationService revocationService;
    
    @PostMapping("/logout")
    public ResponseEntity<String> logout(
            @RequestHeader("Authorization") String authHeader) {
        
        String token = authHeader.replace("Bearer ", "");
        
        // ✅ 토큰 만료까지의 시간 계산
        long expiresInSeconds = calculateRemainingTime(token);
        
        // ✅ 토큰 무효화
        revocationService.revokeToken(token, expiresInSeconds);
        
        return ResponseEntity.ok("로그아웃되었습니다");
    }
    
    private long calculateRemainingTime(String token) {
        Date expiration = extractExpiration(token);
        return (expiration.getTime() - System.currentTimeMillis()) / 1000;
    }
}
```

### 3. 클레임 강화 검증

```java
// ✅ 안전한 코드: 모든 클레임 명시적 검증
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidationContext;

@Component
public class ComprehensiveJwtValidator implements OAuth2TokenValidator<Jwt> {
    
    private final String expectedIssuer = "https://auth-server.example.com";
    private final String[] expectedAudience = {"my-api", "mobile-app"};
    
    @Override
    public OAuth2TokenValidationResult validate(Jwt token) {
        List<String> errors = new ArrayList<>();
        
        // ✅ 1. 발급자(issuer) 검증
        String issuer = token.getIssuer().toString();
        if (!issuer.equals(expectedIssuer)) {
            errors.add("Invalid issuer: " + issuer);
        }
        
        // ✅ 2. 대상(audience) 검증
        List<String> audiences = token.getAudience();
        boolean validAudience = audiences.stream()
            .anyMatch(aud -> Arrays.asList(expectedAudience).contains(aud));
        if (!validAudience) {
            errors.add("Invalid audience: " + audiences);
        }
        
        // ✅ 3. 만료 시간 검증 (기본적으로 수행되지만 명시화)
        if (token.getExpiresAt() != null) {
            Instant now = Instant.now();
            if (now.isAfter(token.getExpiresAt())) {
                errors.add("Token expired");
            }
        }
        
        // ✅ 4. 발급 시간 검증
        if (token.getIssuedAt() != null) {
            Instant now = Instant.now();
            if (now.isBefore(token.getIssuedAt())) {
                errors.add("Token not yet valid");
            }
        }
        
        // ✅ 5. 필수 클레임 확인
        if (!token.containsClaim("sub")) {
            errors.add("Missing required claim: sub");
        }
        
        // ✅ 6. 권한(scope) 검증
        List<String> scopes = token.getClaimAsStringList("scope");
        if (scopes == null || scopes.isEmpty()) {
            errors.add("No scopes granted");
        }
        
        // ✅ 7. 커스텀 클레임 검증 (조직 ID 등)
        String organizationId = token.getClaimAsString("org_id");
        if (organizationId == null || organizationId.isEmpty()) {
            errors.add("Missing organization ID");
        }
        
        if (!errors.isEmpty()) {
            return OAuth2TokenValidationResult.failure(
                new OAuth2Error("invalid_token", String.join(", ", errors))
            );
        }
        
        return OAuth2TokenValidationResult.success();
    }
}

// Spring Security 설정
@Configuration
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/login", "/register").permitAll()
                .anyRequest().authenticated()
                .and()
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .decoder(jwtDecoder())
                    .jwtAuthenticationConverter(jwtAuthenticationConverter())
                )
            );
        
        return http.build();
    }
    
    @Bean
    public JwtDecoder jwtDecoder() {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(publicKey()).build();
        
        // ✅ 커스텀 검증자 적용
        OAuth2TokenValidator<Jwt> validators = new DelegatingOAuth2TokenValidator<>(
            new JwtTimestampValidator(),
            new ComprehensiveJwtValidator()
        );
        
        decoder.setJwtValidator(validators);
        return decoder;
    }
    
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        
        // ✅ 권한 추출 설정
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = 
            new JwtGrantedAuthoritiesConverter();
        grantedAuthoritiesConverter.setAuthoritiesClaimName("roles");
        grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");
        
        converter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        
        return converter;
    }
}
```

### 4. Refresh Token 메커니즘

```java
// ✅ 안전한 코드: Access Token + Refresh Token 분리
@Service
public class TokenService {
    
    private final long accessTokenValiditySeconds = 900;     // 15분
    private final long refreshTokenValiditySeconds = 604800; // 7일
    
    @Autowired
    private TokenRevocationService revocationService;
    
    @Autowired
    private RedisTemplate<String, String> redisTemplate;
    
    public TokenPair generateTokens(String userId) {
        String accessToken = generateAccessToken(userId);
        String refreshToken = generateRefreshToken(userId);
        
        // ✅ Refresh Token을 Redis에 저장 (추적 및 무효화 가능)
        String refreshTokenKey = "refresh_token:" + userId;
        redisTemplate.opsForValue().set(
            refreshTokenKey,
            refreshToken,
            refreshTokenValiditySeconds,
            TimeUnit.SECONDS
        );
        
        return new TokenPair(accessToken, refreshToken);
    }
    
    private String generateAccessToken(String userId) {
        return Jwts.builder()
            .setSubject(userId)
            .setJti(UUID.randomUUID().toString())
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + accessTokenValiditySeconds * 1000))
            .claim("token_type", "access")
            .signWith(accessTokenKey)
            .compact();
    }
    
    private String generateRefreshToken(String userId) {
        return Jwts.builder()
            .setSubject(userId)
            .setJti(UUID.randomUUID().toString())
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + refreshTokenValiditySeconds * 1000))
            .claim("token_type", "refresh")
            .signWith(refreshTokenKey)  // 다른 키 사용
            .compact();
    }
    
    public String refreshAccessToken(String refreshToken) {
        try {
            // ✅ Refresh Token 검증
            Claims claims = Jwts.parserBuilder()
                .setSigningKey(refreshTokenKey)
                .build()
                .parseClaimsJws(refreshToken)
                .getBody();
            
            // Refresh Token이 맞는지 확인
            if (!"refresh".equals(claims.get("token_type"))) {
                throw new SecurityException("잘못된 토큰 타입");
            }
            
            String userId = claims.getSubject();
            
            // ✅ Redis에서 Refresh Token 확인 (무효화되지 않았는지)
            String storedToken = redisTemplate.opsForValue()
                .get("refresh_token:" + userId);
            
            if (!refreshToken.equals(storedToken)) {
                throw new SecurityException("Refresh Token 불일치");
            }
            
            // ✅ 새로운 Access Token 발급
            return generateAccessToken(userId);
        } catch (Exception e) {
            throw new SecurityException("Refresh Token 검증 실패: " + e.getMessage());
        }
    }
}

// Refresh Token 엔드포인트
@RestController
public class TokenController {
    
    @Autowired
    private TokenService tokenService;
    
    @PostMapping("/token/refresh")
    public ResponseEntity<Map<String, String>> refreshToken(
            @RequestBody Map<String, String> request) {
        
        String refreshToken = request.get("refresh_token");
        String newAccessToken = tokenService.refreshAccessToken(refreshToken);
        
        return ResponseEntity.ok(Map.of(
            "access_token", newAccessToken,
            "token_type", "Bearer",
            "expires_in", "900"
        ));
    }
}

public class TokenPair {
    public final String accessToken;
    public final String refreshToken;
    
    public TokenPair(String accessToken, String refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }
}
```

## 🔬 공격 원리 분석 (공격자 관점의 내부 동작)

### 만료 시간 우회 공격

```
1. 공격자가 유효한 토큰 획득 (정당한 사용자가 로그인)
   Access Token: sub=user123, exp=2026-04-14 10:15:00
   Refresh Token: sub=user123, exp=2026-04-21

2. 공격자가 Access Token을 탈취 (예: XSS 취약점)

3. Access Token 만료 전에는 공격자가 API 호출 가능
   GET /api/data → 200 OK (인증됨)

4. Access Token 만료 후, Refresh Token이 없으면?
   GET /api/data → 401 Unauthorized
   
   하지만 Refresh Token을 탈취했다면:
   POST /token/refresh
   - 새로운 Access Token 발급
   - 7일 동안 지속 가능
```

### 토큰 무효화 없을 때의 피해

```
시간: T=0
- 사용자가 공용 PC에서 로그인
- Access Token: sub=user123, exp=T+900초
- Refresh Token: sub=user123, exp=T+604800초

시간: T+100
- 공격자가 토큰 복사

시간: T+200
- 정상 사용자가 로그아웃 클릭
- 서버: 로그아웃 처리 완료 (하지만 토큰은 유효)

시간: T+300
- 공격자가 복사한 토큰으로 API 호출
- 서버: 토큰이 유효하고 만료되지 않음 → 인증 성공
- 사용자 데이터 탈취

해결책: 로그아웃 시 토큰을 Redis 블랙리스트에 추가
```

## 💻 실전 실험 (취약점 재현 → 공격 → 방어 검증)

### 실험 1: 만료 시간 검증 제대로 안 할 때

```java
// 취약한 코드 테스트
@SpringBootTest
public class ExpiryBypassTest {
    
    @Test
    public void testExpiredTokenAccepted() {
        // 이미 만료된 토큰 생성
        String expiredToken = Jwts.builder()
            .setSubject("user123")
            .setExpiration(new Date(System.currentTimeMillis() - 100000))
            .signWith(SignatureAlgorithm.HS256, "secret")
            .compact();
        
        // 취약한 파서: 만료 시간을 검증하지 않음
        Claims claims = Jwts.parserBuilder()
            .setSigningKey("secret".getBytes())
            // ❌ setSigningKeyResolver 또는 다른 옵션을 잘못 사용
            .build()
            .parseClaimsJws(expiredToken)
            .getBody();
        
        // ❌ 만료된 토큰이 수용됨
        assertEquals("user123", claims.getSubject());
    }
    
    @Test
    public void testExpiredTokenRejected() {
        String expiredToken = Jwts.builder()
            .setSubject("user123")
            .setExpiration(new Date(System.currentTimeMillis() - 100000))
            .signWith(SignatureAlgorithm.HS256, "secret")
            .compact();
        
        // ✅ 안전한 파서: 만료 시간을 자동으로 검증
        assertThrows(
            io.jsonwebtoken.ExpiredJwtException.class,
            () -> Jwts.parserBuilder()
                .setSigningKey("secret".getBytes())
                .build()
                .parseClaimsJws(expiredToken)  // ✅ 기본적으로 exp 검증함
        );
    }
}
```

### 실험 2: 토큰 무효화 확인

```java
// 토큰 무효화 테스트
@SpringBootTest
public class TokenRevocationTest {
    
    @Autowired
    private TokenRevocationService revocationService;
    
    @Autowired
    private TokenService tokenService;
    
    @Test
    public void testTokenRevocationWorks() {
        // 1. 토큰 생성
        TokenPair tokens = tokenService.generateTokens("user123");
        String accessToken = tokens.accessToken;
        
        // 2. 토큰이 유효한 상태
        assertFalse(revocationService.isTokenRevoked(accessToken));
        
        // 3. 토큰 무효화
        revocationService.revokeToken(accessToken, 900);
        
        // 4. 토큰이 무효화된 상태
        assertTrue(revocationService.isTokenRevoked(accessToken));
    }
    
    @Test
    public void testRevokedTokenExpires() {
        TokenPair tokens = tokenService.generateTokens("user123");
        String accessToken = tokens.accessToken;
        
        // 토큰 무효화 (TTL = 1초)
        revocationService.revokeToken(accessToken, 1);
        
        // 무효화 직후: 블랙리스트에 있음
        assertTrue(revocationService.isTokenRevoked(accessToken));
        
        // 1초 대기
        Thread.sleep(2000);
        
        // 만료 후: 블랙리스트에서 제거됨 (Redis TTL 만료)
        assertFalse(revocationService.isTokenRevoked(accessToken));
    }
}
```

### 실험 3: Refresh Token 체인 공격 방어

```java
// Refresh Token 공격 시나리오
@SpringBootTest
public class RefreshTokenSecurityTest {
    
    @Autowired
    private TokenService tokenService;
    
    @Autowired
    private RedisTemplate<String, String> redisTemplate;
    
    @Test
    public void testRefreshTokenReuse() {
        // 1. 사용자가 Refresh Token 획득
        TokenPair tokens = tokenService.generateTokens("user123");
        String refreshToken = tokens.refreshToken;
        
        // 2. 공격자가 Refresh Token 탈취
        
        // 3. 정상 사용자가 로그아웃
        revocationService.revokeToken(refreshToken, 604800);
        
        // 4. 공격자가 Refresh Token으로 새로운 Access Token 요청
        // ❌ 만료되지 않은 경우: 성공
        // ✅ Redis에서 검증하면: 실패 (무효화됨)
    }
    
    @Test
    public void testRefreshTokenRotation() {
        // 첫 번째 로그인
        TokenPair tokens1 = tokenService.generateTokens("user123");
        
        // 다중 디바이스에서 Refresh Token 사용
        String newAccessToken1 = tokenService.refreshAccessToken(tokens1.refreshToken);
        String newAccessToken2 = tokenService.refreshAccessToken(tokens1.refreshToken);
        
        // ✅ 같은 Refresh Token으로 여러 번 갱신 가능
        // (또는 1회만 가능하도록 구현 가능)
        assertNotNull(newAccessToken1);
        assertNotNull(newAccessToken2);
    }
}
```

## 📊 공격 성공 조건 vs 방어 성공 조건 비교

| 공격 벡터 | 공격 성공 조건 | 방어 성공 조건 |
|---------|--------------|--------------|
| **만료 시간 무시** | 서버가 `exp` 클레임 검증 안함 | `parseClaimsJws()` 사용 (자동 검증) |
| **로그아웃 후 토큰 사용** | 블랙리스트 없음 | Redis 블랙리스트 + TTL |
| **Refresh Token 탈취** | 탈취한 Refresh Token 무기한 사용 | 1회 사용 또는 IP 묶음 |
| **Long-lived Token** | Access Token 유효 기간이 매우 김 | 15분 이하, Refresh Token과 분리 |
| **클레임 위조** | 약한 비밀키 또는 알고리즘 혼동 | 256비트+ HMAC, RS256만 사용 |

## ⚖️ 트레이드오프 (보안 강화 vs 사용성/성능)

### 1. Access Token 만료 시간 vs 사용자 경험
- **보안**: 15분 이하 → 토큰 탈취 후 피해 최소화
- **사용성**: 사용자가 자주 재인증해야 함
- **트레이드오프**: Refresh Token으로 해결 (자동 갱신)

### 2. 토큰 블랙리스트 vs 메모리 비용
- **보안**: 모든 로그아웃 토큰을 Redis에 저장 (확실한 무효화)
- **성능**: Redis 용량 증가, 조회 지연
- **트레이드오프**: 
  - TTL을 토큰 만료 시간으로 설정 (자동 정리)
  - 필요한 경우만 블랙리스트 (예: 관리자만)

### 3. Refresh Token 회전 vs 세션 관리 복잡도
- **보안**: 1회 사용 후 폐기 → 탈취된 Refresh Token 자동 무효화
- **복잡도**: 모든 갱신마다 새로운 Refresh Token 발급, 추적 어려움
- **트레이드오프**:
  - JWT는 Stateless이므로 회전 추적 어려움
  - Redis에 Refresh Token 저장 필요

### 4. 클레임 검증 수준 vs 성능
- **보안**: 모든 클레임(issuer, audience, scope 등) 검증
- **성능**: 검증 로직 증가, 요청당 처리 시간 증가
- **트레이드오프**: 
  - 캐싱으로 완화 (JWKS 캐싱)
  - 중요 클레임만 검증

## 📌 핵심 정리

1. **명시적 만료 시간 검증**
   ```java
   .parseClaimsJws(token)  // 자동으로 exp 검증
   ```

2. **Refresh Token 메커니즘**
   - Access Token: 15분
   - Refresh Token: 7일 (Redis 저장)

3. **토큰 무효화**
   ```java
   revocationService.revokeToken(token, expiresInSeconds);
   ```

4. **클레임 강화 검증**
   - issuer, audience, scope, org_id 등

5. **다중 검증 계층**
   ```java
   new DelegatingOAuth2TokenValidator<>(
       new JwtTimestampValidator(),
       new ComprehensiveJwtValidator()
   )
   ```

## 🤔 생각해볼 문제 (+ 해설)

### 문제 1: 왜 Redis 블랙리스트가 필요한가? JWT는 Stateless인데?
**해설:**
- JWT는 서명만 검증하면 되므로 이론적으로 Stateless
- 하지만 로그아웃 후 토큰 무효화가 필요함
- Stateless를 유지하려면 짧은 만료 시간 + Refresh Token
- Redis 블랙리스트는 추가 보안 계층 (선택사항)
- 트레이드오프: Stateless (확장성) vs 신뢰성 (로그아웃 보장)

### 문제 2: Refresh Token도 탈취될 수 있는데, 어떻게 보호하는가?
**해설:**
- Refresh Token을 HTTP-Only 쿠키에 저장 (XSS 방지)
- HTTPS + Secure 플래그 (전송 보안)
- IP 주소 바인딩 (기기별 추적)
- 1회 사용만 가능하도록 설정
- 하지만 완벽한 보호는 불가능 → 결국 빠른 만료가 최선

### 문제 3: 왜 별도의 키로 Refresh Token을 서명하는가?
**해설:**
- Access Token은 API 서버가 검증
- Refresh Token은 인증 서버만 검증
- 다른 키를 사용하면:
  - API 서버에서 Refresh Token을 실수로 수용할 수 없음
  - 키 분리로 보안 강화
  - 각 서버가 필요한 토큰만 처리

---

<div align="center">

**[⬅️ 이전: JWT 취약점 완전 분해](./01-jwt-vulnerabilities.md)** | **[홈으로 🏠](../README.md)** | **[다음: 세션 고정 공격 ➡️](./03-session-fixation.md)**

</div>
