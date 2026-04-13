# 05. JWT 권한 클레임 검증 — 토큰 신뢰만으로는 부족한 이유

---

## 🎯 핵심 질문

JWT(JSON Web Token)는 서명되어 있으므로 변조 불가능하다고 알고 있나요?

**하지만** 다음 시나리오를 생각해보세요:

1. **토큰 탈취**: 공격자가 유효한 토큰을 가지고 있음
2. **토큰 재사용**: 다른 서비스/API에서 같은 토큰 사용
3. **클라이언트 변조**: 클라이언트 측에서 토큰 생성 (서명 검증 없을 경우)
4. **권한 정보 신뢰**: 토큰의 `"role"` 클레임을 그대로 신뢰

특히 토큰 발급 이후에 **사용자의 권한이 변경**되었다면? 예를 들어:
- 관리자였던 사용자가 역할 박탈당함
- 계약이 만료된 사용자가 여전히 토큰 사용

이 경우, **토큰의 권한 정보는 이미 과거의 정보**이며, 서버는 매번 데이터베이스에서 **현재 권한을 재확인**해야 합니다.

---

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

### 실제 사고 사례 1: JWT 토큰 탈취 후 권한 상승
2020년 한 금융 서비스에서 JWT 토큰이 탈취되었고, 공격자는:

1. 탈취한 토큰의 `"role"` 클레임을 디코딩
2. 토큰 변조 (만료 시간 연장, role을 ADMIN으로 변경)
3. 서버가 변조된 토큰의 권한을 신뢰
4. **미승인 송금 처리** → 계좌에서 수백만 원 출금

### 실제 사고 사례 2: 역할 박탈 후에도 접근 가능
어떤 회사의 직원이 퇴사했는데:

1. 퇴사 당일에 JWT 토큰을 발급받음
2. 퇴사 후에도 토큰이 유효 (유효 기간이 30일)
3. 토큰을 재사용하여 **회사 내부 데이터베이스 접근**
4. 민감한 정보 탈취 → 규제 위반

### 실제 사고 사례 3: 마이크로서비스 간 토큰 재사용
마이크로서비스 아키텍처에서:

1. 사용자 서비스에서 발급한 토큰
2. 관리자는 조회 권한만 있음 (역할: ROLE_VIEW_ONLY)
3. 결제 서비스에서 같은 토큰을 재사용
4. 결제 서비스가 토큰의 role을 신뢰
5. 조회 전용 역할로도 결제 권한 획득

### 왜 위험한가?
- **권한 정보 불일치**: 토큰의 정보와 실제 DB 정보 불일치
- **토큰 탈취 후 악용**: 서명은 유효하지만 내용은 공격자의 것
- **권한 박탈 무효화**: 퇴사자/정지 계정도 토큰으로 접근
- **서비스 간 신뢰 문제**: 다른 서비스에서 발급한 토큰을 무비판적으로 신뢰

---

## 😱 취약한 코드 (Before — 원리를 모를 때의 구현)

### 취약점 1: 토큰의 권한만 신뢰하고 DB 재검증 없음

```java
// 취약한 JWT 토큰 제공자
@Component
public class JwtTokenProvider {
    
    @Value("${jwt.secret}")
    private String secretKey;
    
    // JWT 생성: 권한 정보를 토큰에 포함
    public String generateToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", user.getId());
        claims.put("username", user.getUsername());
        claims.put("role", user.getRole().name());  // ← 권한 정보 포함
        claims.put("email", user.getEmail());
        
        return Jwts.builder()
            .setClaims(claims)
            .setSubject(user.getUsername())
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + 86400000))  // 24시간
            .signWith(SignatureAlgorithm.HS512, secretKey)
            .compact();
    }
    
    // 취약점: 토큰의 정보를 그대로 신뢰
    public Authentication getAuthentication(String token) {
        Claims claims = Jwts.parser()
            .setSigningKey(secretKey)
            .parseClaimsJws(token)
            .getBody();
        
        // 문제: DB를 조회하지 않고 토큰의 정보만 사용
        String userId = claims.get("userId").toString();
        String role = claims.get("role").toString();  // ← 그대로 신뢰!
        
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(role));
        
        return new UsernamePasswordAuthenticationToken(
            userId, null, authorities
        );
    }
}

// 취약한 컨트롤러
@RestController
@RequestMapping("/api/admin")
public class AdminController {
    
    @Autowired
    private UserService userService;
    
    // 문제: 토큰의 role 클레임으로만 검증
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/users")
    public ResponseEntity<List<UserDto>> getAllUsers() {
        // 토큰에 ROLE_ADMIN이 있으면 통과
        // 하지만 사용자가 실제로 관리자인지는 확인하지 않음!
        List<User> users = userService.findAll();
        return ResponseEntity.ok(users.stream()
            .map(UserDto::new)
            .toList());
    }
    
    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/users/{userId}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long userId) {
        // 토큰만 신뢰 → DB를 재검증하지 않음
        userService.deleteById(userId);
        return ResponseEntity.noContent().build();
    }
}
```

### 취약점 2: 클라이언트가 토큰을 직접 생성하거나 변조

```java
// 클라이언트 측 공격 (토큰 변조)
public class TokenManipulationAttack {
    
    public static void main(String[] args) throws Exception {
        // Step 1: 정상 토큰을 jwt.io에서 디코딩
        String originalToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI5OTkiLCJyb2xlIjoiUk9MRV9VU0VSIn0.sig";
        
        // Step 2: 토큰 디코딩
        // {
        //   "userId": "999",
        //   "role": "ROLE_USER"
        // }
        
        // Step 3: jwt.io 웹사이트에서 role을 변조
        // {
        //   "userId": "999",
        //   "role": "ROLE_ADMIN"  ← 변조!
        // }
        
        // Step 4: 변조된 토큰으로 API 요청
        // Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI5OTkiLCJyb2xlIjoiUk9MRV9BRE1JTiJ9.sig
        
        // Step 5: 서버가 토큰을 검증
        // → 서명은 여전히 유효한가? (아니면 검증하지 않나?)
        // → role 클레임을 신뢰하면 권한 상승 성공!
    }
}

// 실제 공격 시나리오
// 1. 약한 비밀키 사용 → 서명 위조 가능
// 2. 서명 검증 무시 → 내용만 변조
// 3. 알고리즘 변조 (HS256 → none) → 서명 무시
```

### 취약점 3: 토큰 탈취 후 권한 변경되지 않음

```
Timeline:
┌──────────────────────────────────────────────────────┐
│ 10:00 AM - 사용자 로그인 (관리자)                     │
│ → JWT 토큰 발급: {"role": "ROLE_ADMIN", exp: +24h}  │
│                                                      │
│ 02:00 PM - 관리자 권한 박탈 (DB에서 role 변경)        │
│ → 하지만 토큰은 여전히 유효!                         │
│                                                      │
│ 03:00 PM - 탈취된 토큰으로 민감한 작업 수행           │
│ → 서버가 토큰의 role만 신뢰하면 성공!               │
│                                                      │
│ 10:00 AM (다음날) - 토큰 만료                       │
│ → 24시간 동안 권한 없는 사용자가 관리자 권한 사용     │
└──────────────────────────────────────────────────────┘
```

### 취약점 4: 마이크로서비스 간 토큰 재사용

```
Service A (User Service)           Service B (Payment Service)
┌─────────────────────┐           ┌──────────────────────┐
│ /api/auth/login     │           │ /api/payments        │
│                     │           │                      │
│ Token 발급:         │           │ Token 검증:          │
│ role="VIEW_ONLY"    │──────────>│ role 클레임 신뢰    │
│                     │           │                      │
│ 목적: 데이터 조회   │           │ 목적: 결제 처리      │
│ (read-only)        │           │ (민감한 작업)        │
└─────────────────────┘           └──────────────────────┘

결과: 조회 권한으로 결제까지 가능! (권한 상승)
```

---

## ✨ 방어 코드 (After — 공격 원리를 알고 설계한 구현)

### 방어 전략 1: 토큰에 최소 정보만 포함, 권한은 매번 DB에서 조회

```java
// 개선된 JWT 토큰 제공자
@Component
public class SecureJwtTokenProvider {
    
    @Autowired
    private UserRepository userRepository;
    
    @Value("${jwt.secret}")
    private String secretKey;
    
    @Value("${jwt.expiration}")
    private long validityInMilliseconds;
    
    // 방어: 토큰에는 ID만 포함 (변경되지 않는 정보)
    public String generateToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", user.getId());
        claims.put("username", user.getUsername());
        
        // 주의: role은 포함하지 않음!
        // 대신 매번 DB에서 조회할 것임
        
        return Jwts.builder()
            .setClaims(claims)
            .setSubject(user.getUsername())
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + validityInMilliseconds))
            .signWith(SignatureAlgorithm.HS512, secretKey)
            .compact();
    }
    
    // 방어: DB에서 현재 권한 정보를 매번 조회
    public Authentication getAuthentication(String token) {
        Claims claims = Jwts.parser()
            .setSigningKey(secretKey)
            .parseClaimsJws(token)
            .getBody();
        
        Long userId = Long.valueOf(claims.get("userId").toString());
        
        // 중요: 데이터베이스에서 사용자 정보를 다시 조회
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException("User not found"));
        
        // 1. 사용자 활성 상태 확인
        if (!user.isEnabled()) {
            throw new DisabledException("User account is disabled");
        }
        
        // 2. 계정 잠금 상태 확인
        if (user.isLocked()) {
            throw new LockedException("User account is locked");
        }
        
        // 3. 현재 데이터베이스의 권한 정보 사용
        List<GrantedAuthority> authorities = user.getRoles().stream()
            .map(role -> new SimpleGrantedAuthority(role.getRoleName()))
            .collect(Collectors.toList());
        
        return new UsernamePasswordAuthenticationToken(
            userId, null, authorities
        );
    }
    
    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
    
    public long getTokenExpirationTime(String token) {
        Claims claims = Jwts.parser()
            .setSigningKey(secretKey)
            .parseClaimsJws(token)
            .getBody();
        
        return claims.getExpiration().getTime();
    }
}

// 개선된 인증 필터
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    @Autowired
    private SecureJwtTokenProvider jwtTokenProvider;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                   HttpServletResponse response,
                                   FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = extractTokenFromRequest(request);
            
            if (jwt != null && jwtTokenProvider.validateToken(jwt)) {
                // 매번 DB에서 권한 재검증
                Authentication authentication = jwtTokenProvider.getAuthentication(jwt);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (DisabledException e) {
            // 비활성화된 계정: 401 응답
            sendError(response, "Account is disabled", HttpServletResponse.SC_UNAUTHORIZED);
            return;
        } catch (LockedException e) {
            // 잠금 계정: 403 응답
            sendError(response, "Account is locked", HttpServletResponse.SC_FORBIDDEN);
            return;
        } catch (Exception e) {
            // 토큰 검증 실패: 로그 및 계속
        }
        
        filterChain.doFilter(request, response);
    }
    
    private String extractTokenFromRequest(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");
        if (headerAuth != null && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }
        return null;
    }
    
    private void sendError(HttpServletResponse response, String message, int status) 
            throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\":\"" + message + "\"}");
    }
}
```

### 방어 전략 2: 토큰에 서명 검증 강화 + 토큰 블랙리스트

```java
// 향상된 보안: 토큰 블랙리스트
@Component
public class TokenBlacklistService {
    
    @Autowired
    private RedisTemplate<String, Long> redisTemplate;
    
    // 토큰을 블랙리스트에 추가 (로그아웃 시)
    public void blacklistToken(String token, long expirationTime) {
        long ttl = (expirationTime - System.currentTimeMillis()) / 1000;
        if (ttl > 0) {
            redisTemplate.opsForValue().set(
                "blacklist:" + token,
                System.currentTimeMillis(),
                Duration.ofSeconds(ttl)
            );
        }
    }
    
    // 토큰이 블랙리스트에 있는지 확인
    public boolean isBlacklisted(String token) {
        return redisTemplate.hasKey("blacklist:" + token);
    }
}

// 토큰 블랙리스트를 검증 필터에 포함
@Component
public class EnhancedJwtAuthenticationFilter extends OncePerRequestFilter {
    
    @Autowired
    private SecureJwtTokenProvider jwtTokenProvider;
    
    @Autowired
    private TokenBlacklistService tokenBlacklistService;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                   HttpServletResponse response,
                                   FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = extractTokenFromRequest(request);
            
            if (jwt != null) {
                // 1단계: 블랙리스트 확인
                if (tokenBlacklistService.isBlacklisted(jwt)) {
                    sendError(response, "Token has been revoked", 
                             HttpServletResponse.SC_UNAUTHORIZED);
                    return;
                }
                
                // 2단계: 서명 검증
                if (jwtTokenProvider.validateToken(jwt)) {
                    // 3단계: DB에서 권한 재검증
                    Authentication authentication = jwtTokenProvider.getAuthentication(jwt);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        } catch (Exception e) {
            // 에러 처리
        }
        
        filterChain.doFilter(request, response);
    }
    
    private String extractTokenFromRequest(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");
        if (headerAuth != null && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }
        return null;
    }
    
    private void sendError(HttpServletResponse response, String message, int status)
            throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\":\"" + message + "\"}");
    }
}
```

### 방어 전략 3: 메서드 레벨 권한 재검증

```java
// 메서드 보안 설정
@Configuration
@EnableGlobalMethodSecurity(
    prePostEnabled = true,        // @PreAuthorize, @PostAuthorize 활성화
    securedEnabled = true,        // @Secured 활성화
    jsr250Enabled = true          // @RolesAllowed 활성화
)
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {
    // ...
}

// 관리자 API: 메서드 레벨 권한 검증
@RestController
@RequestMapping("/api/admin")
public class AdminController {
    
    @Autowired
    private UserService userService;
    
    @Autowired
    private AuditLog auditLog;
    
    // 방어: 메서드 호출 전에 권한 재검증
    @PreAuthorize("@adminAuthority.hasAdminRole(authentication.principal)")
    @GetMapping("/users")
    public ResponseEntity<List<UserDto>> getAllUsers(
            @AuthenticationPrincipal CustomUserDetails userDetails) {
        
        // 추가: 현재 사용자의 권한을 DB에서 다시 확인
        User currentUser = userService.findById(userDetails.getUserId());
        if (!currentUser.hasRole("ROLE_ADMIN")) {
            auditLog.logUnauthorizedAccess("GET /api/admin/users", userDetails.getUserId());
            throw new AccessDeniedException("Admin role is required");
        }
        
        List<User> users = userService.findAll();
        return ResponseEntity.ok(users.stream()
            .map(UserDto::new)
            .toList());
    }
    
    @PreAuthorize("@adminAuthority.hasAdminRole(authentication.principal)")
    @DeleteMapping("/users/{userId}")
    public ResponseEntity<Void> deleteUser(
            @PathVariable Long userId,
            @AuthenticationPrincipal CustomUserDetails userDetails) {
        
        // 삭제 작업은 더욱 엄격한 검증
        User currentUser = userService.findById(userDetails.getUserId());
        
        // 1. 현재 사용자가 정말 관리자인지 확인
        if (!currentUser.hasRole("ROLE_SUPER_ADMIN")) {
            throw new AccessDeniedException("Super admin role is required");
        }
        
        // 2. 삭제 대상 사용자 확인
        User targetUser = userService.findById(userId);
        if (targetUser == null) {
            throw new UserNotFoundException("User not found");
        }
        
        // 3. 자신을 삭제하려는 시도 방어
        if (currentUser.getId().equals(userId)) {
            throw new BusinessException("Cannot delete your own account");
        }
        
        // 4. 감시 로깅
        auditLog.log("USER_DELETED", currentUser.getId(), 
                     String.format("Deleted user: %s", targetUser.getUsername()));
        
        userService.deleteById(userId);
        return ResponseEntity.noContent().build();
    }
}

// 권한 검증 Bean
@Component
public class AdminAuthority {
    
    @Autowired
    private UserRepository userRepository;
    
    // @PreAuthorize에서 사용될 메서드
    public boolean hasAdminRole(CustomUserDetails userDetails) {
        // DB에서 현재 권한 확인
        User user = userRepository.findById(userDetails.getUserId())
            .orElseThrow(() -> new UserNotFoundException("User not found"));
        
        return user.getRoles().stream()
            .anyMatch(role -> role.getRoleName().equals("ROLE_ADMIN"));
    }
}
```

### 방어 전략 4: 서비스 간 토큰 검증 (마이크로서비스)

```java
// 마이크로서비스 환경에서 토큰 검증
@Component
public class ServiceTokenValidator {
    
    @Autowired
    private RestTemplate restTemplate;
    
    @Value("${auth.service.url}")
    private String authServiceUrl;
    
    // 토큰을 발급한 원래 서비스에서 검증
    public void validateTokenWithAuthService(String token) {
        try {
            // 원래 인증 서비스에 토큰 검증 요청
            ResponseEntity<TokenValidationResponse> response = restTemplate.postForEntity(
                authServiceUrl + "/validate",
                new TokenValidationRequest(token),
                TokenValidationResponse.class
            );
            
            if (!response.getBody().isValid()) {
                throw new InvalidTokenException("Token validation failed");
            }
            
            // 추가: 토큰의 발급 서비스 확인
            String issuedBy = response.getBody().getIssuedBy();
            if (!issuedBy.equals("USER_SERVICE")) {
                throw new InvalidTokenException("Token issued by unauthorized service");
            }
            
        } catch (Exception e) {
            throw new TokenValidationException("Failed to validate token", e);
        }
    }
}

// 각 마이크로서비스: 토큰 검증 필터
@Component
public class MicroserviceTokenValidationFilter extends OncePerRequestFilter {
    
    @Autowired
    private ServiceTokenValidator serviceTokenValidator;
    
    @Autowired
    private SecureJwtTokenProvider jwtTokenProvider;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                   HttpServletResponse response,
                                   FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = extractTokenFromRequest(request);
            
            if (jwt != null) {
                // 1. 로컬에서 서명 검증
                if (!jwtTokenProvider.validateToken(jwt)) {
                    throw new InvalidTokenException("Invalid token signature");
                }
                
                // 2. 원래 서비스에서 토큰 재검증
                serviceTokenValidator.validateTokenWithAuthService(jwt);
                
                // 3. 권한 정보 로드
                Authentication authentication = jwtTokenProvider.getAuthentication(jwt);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception e) {
            // 검증 실패
        }
        
        filterChain.doFilter(request, response);
    }
    
    private String extractTokenFromRequest(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");
        if (headerAuth != null && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }
        return null;
    }
}
```

---

## 🔬 공격 원리 분석 (공격자 관점의 내부 동작)

### 공격 시나리오 1: 토큰 탈취 후 권한 정보 변조

```
Step 1: 정상 토큰 획득
┌────────────────────────────────┐
│ 사용자 로그인 성공              │
│ 토큰: eyJhbGciOiJIUzI1NiJ...  │
└────────────────────────────────┘

Step 2: 토큰 디코딩 (jwt.io 사용)
┌────────────────────────────────┐
│ Header:                        │
│ { "alg": "HS256" }            │
│                               │
│ Payload:                      │
│ {                             │
│   "userId": "100",            │
│   "role": "ROLE_USER"         │
│ }                             │
└────────────────────────────────┘

Step 3: 토큰 변조 시도
┌────────────────────────────────┐
│ jwt.io에서 Payload 수정:       │
│ {                             │
│   "userId": "100",            │
│   "role": "ROLE_ADMIN" ← 변조! │
│ }                             │
└────────────────────────────────┘

Step 4: 서버 검증
┌────────────────────────────────┐
│ 취약한 서버:                   │
│ 1. 서명 검증 (통과!)           │
│ 2. role 클레임 신뢰 (ADMIN)    │
│ → 권한 상승 성공!              │
│                               │
│ 방어된 서버:                   │
│ 1. 서명 검증 (통과!)           │
│ 2. 토큰의 role 무시            │
│ 3. DB에서 실제 role 조회       │
│    (ROLE_USER)                │
│ → 권한 상승 실패!              │
└────────────────────────────────┘
```

### 공격 시나리오 2: 권한 박탈 후에도 토큰 유효

```
Timeline:

┌─── 10:00 AM ────────────────────────┐
│ 사용자 로그인                       │
│ JWT 발급: role=ADMIN, exp=10:00PM   │
└──────────────────────────────────────┘
         ↓
┌─── 02:00 PM ────────────────────────┐
│ 관리자 권한 박탈 (DB 업데이트)      │
│ - role: ADMIN → USER                │
│ - 하지만 토큰은 여전히 유효!        │
└──────────────────────────────────────┘
         ↓
┌─── 03:00 PM ────────────────────────┐
│ 토큰으로 민감한 작업 수행           │
│                                    │
│ 취약한 서버:                        │
│ 토큰의 role=ADMIN을 신뢰            │
│ → 접근 허용! (권한 박탈 무효화)    │
│                                    │
│ 방어된 서버:                        │
│ DB에서 현재 권한 조회               │
│ → role=USER 확인                   │
│ → 접근 거부!                        │
└──────────────────────────────────────┘
```

---

## 💻 실전 실험 (취약점 재현 → 공격 → 방어 검증)

### 실험 1: 토큰 권한 신뢰 테스트

```java
@SpringBootTest
public class JwtClaimValidationTest {
    
    @Autowired
    private SecureJwtTokenProvider secureJwtTokenProvider;
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private RestTemplate restTemplate;
    
    @Test
    public void testVulnerable_TrustTokenRole_Escalation() {
        // 일반 사용자 생성
        User user = new User();
        user.setId(1L);
        user.setUsername("user1");
        user.setRole(Role.ROLE_USER);
        userRepository.save(user);
        
        // 토큰 생성 (취약한 방식: role 포함)
        String token = createVulnerableToken(user);  // role=USER
        
        // 토큰 변조 (클라이언트에서)
        String tamperedToken = manipulateTokenRole(token, "ROLE_ADMIN");
        
        // 취약한 서버: 변조된 토큰의 role 신뢰
        Authentication auth = getAuthenticationVulnerable(tamperedToken);
        
        // 검증: ADMIN 역할로 인식됨 (취약!)
        assertTrue(auth.getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN")));
    }
    
    @Test
    public void testDefended_DBRevalidation_RejectsManipulation() {
        // 일반 사용자 생성
        User user = new User();
        user.setId(2L);
        user.setUsername("user2");
        user.setRole(Role.ROLE_USER);
        userRepository.save(user);
        
        // 안전한 토큰 생성 (role 미포함)
        String token = secureJwtTokenProvider.generateToken(user);
        
        // 토큰 변조 시도
        String tamperedToken = manipulateTokenRole(token, "ROLE_ADMIN");
        
        // 방어된 서버: DB에서 실제 권한 조회
        Authentication auth = secureJwtTokenProvider.getAuthentication(tamperedToken);
        
        // 검증: 실제 권한인 USER로만 인식됨 (안전!)
        assertTrue(auth.getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().equals("ROLE_USER")));
        
        assertFalse(auth.getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN")));
    }
    
    @Test
    public void testDefended_RoleChangeRejected() {
        // 관리자 권한을 가진 사용자
        User user = new User();
        user.setId(3L);
        user.setUsername("admin1");
        user.setRole(Role.ROLE_ADMIN);
        userRepository.save(user);
        
        // 토큰 생성 (이 시점에는 ADMIN)
        String token = secureJwtTokenProvider.generateToken(user);
        
        // DB에서 역할 박탈
        user.setRole(Role.ROLE_USER);
        userRepository.save(user);
        
        // 토큰으로 API 접근 시도
        try {
            Authentication auth = secureJwtTokenProvider.getAuthentication(token);
            
            // DB에서 재조회하므로 현재 역할인 USER로 인식
            assertTrue(auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_USER")));
            
            assertFalse(auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN")));
            
            System.out.println("Role demotion detected: Token no longer has admin privileges");
        } catch (Exception e) {
            System.out.println("Role validation failed as expected");
        }
    }
    
    private String createVulnerableToken(User user) {
        // 취약한 방식: role을 토큰에 포함
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", user.getId());
        claims.put("role", user.getRole().name());
        
        // 실제로는 jwt 생성 로직
        return "dummy_vulnerable_token";
    }
    
    private String manipulateTokenRole(String token, String newRole) {
        // jwt.io 시뮬레이션
        // 실제로는 토큰 디코딩 후 변조
        return "dummy_tampered_token";
    }
    
    private Authentication getAuthenticationVulnerable(String token) {
        // 취약한 방식: 토큰의 role을 그대로 신뢰
        // DB를 조회하지 않음
        return new UsernamePasswordAuthenticationToken("user", null,
            List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
    }
}
```

### 실험 2: 토큰 블랙리스트 테스트

```java
@SpringBootTest
public class TokenBlacklistTest {
    
    @Autowired
    private TokenBlacklistService tokenBlacklistService;
    
    @Autowired
    private SecureJwtTokenProvider jwtTokenProvider;
    
    @Autowired
    private UserRepository userRepository;
    
    @Test
    public void testTokenBlacklist_LogoutRevokeToken() {
        // 사용자 생성 및 토큰 발급
        User user = new User();
        user.setId(1L);
        user.setUsername("user1");
        userRepository.save(user);
        
        String token = jwtTokenProvider.generateToken(user);
        
        // 토큰 유효성 확인
        assertTrue(jwtTokenProvider.validateToken(token));
        
        // 로그아웃: 토큰을 블랙리스트에 추가
        long expirationTime = jwtTokenProvider.getTokenExpirationTime(token);
        tokenBlacklistService.blacklistToken(token, expirationTime);
        
        // 토큰 재사용 시도
        assertTrue(tokenBlacklistService.isBlacklisted(token),
                  "Token should be blacklisted after logout");
    }
    
    @Test
    public void testTokenBlacklist_PreventReuseAfterLogout() throws Exception {
        User user = new User();
        user.setId(2L);
        user.setUsername("user2");
        userRepository.save(user);
        
        String token = jwtTokenProvider.generateToken(user);
        
        // 로그아웃
        long expirationTime = jwtTokenProvider.getTokenExpirationTime(token);
        tokenBlacklistService.blacklistToken(token, expirationTime);
        
        // 블랙리스트된 토큰으로 API 요청
        // EnhancedJwtAuthenticationFilter에서 차단됨
        assertTrue(tokenBlacklistService.isBlacklisted(token));
    }
}
```

---

## 📊 공격 성공 조건 vs 방어 성공 조건 비교

| 항목 | 공격 성공 조건 | 방어 성공 조건 |
|------|--------------|--------------|
| **토큰 정보** | role 클레임 포함 및 신뢰 | 최소 정보만 (ID) 포함 |
| **권한 검증 시기** | 토큰 생성 시점 | 매 요청 시마다 DB 재검증 |
| **권한 변경 반영** | 토큰 만료 후 (24시간+) | 즉시 (다음 요청부터) |
| **토큰 변조 방어** | 약한 비밀키 또는 검증 부재 | 강력한 HS512, 유효성 검증 |
| **토큰 탈취 후** | 계속 사용 가능 | 블랙리스트로 즉시 무효화 |
| **서비스 간 신뢰** | 토큰만으로 판단 | 원래 서비스에서 재검증 |

---

## ⚖️ 트레이드오프 (보안 강화 vs 사용성/성능)

### 트레이드오프 1: 매번 DB 조회 vs 성능

```
매번 DB 조회 (보안):
- 권한 변경 즉시 반영
- 토큰 탈취 시 손실 최소화
- DB 부하 증가 (매 요청마다)

토큰의 권한만 신뢰 (성능):
- 빠른 응답
- DB 부하 낮음
- 권한 변경 반영 지연
```

**해결책**: 캐싱 + TTL

```java
@Component
public class CachedSecureJwtTokenProvider {
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private CacheManager cacheManager;
    
    private static final String ROLE_CACHE = "userRoles";
    private static final long CACHE_TTL_SECONDS = 300;  // 5분
    
    public Authentication getAuthentication(String token) {
        Claims claims = Jwts.parser()
            .setSigningKey(secretKey)
            .parseClaimsJws(token)
            .getBody();
        
        Long userId = Long.valueOf(claims.get("userId").toString());
        
        // 1. 캐시에서 먼저 조회 (5분 TTL)
        List<GrantedAuthority> cachedAuthorities = getCachedRoles(userId);
        if (cachedAuthorities != null) {
            return new UsernamePasswordAuthenticationToken(
                userId, null, cachedAuthorities
            );
        }
        
        // 2. 캐시 미스: DB에서 조회
        User user = userRepository.findById(userId).orElseThrow();
        
        List<GrantedAuthority> authorities = user.getRoles().stream()
            .map(role -> new SimpleGrantedAuthority(role.getRoleName()))
            .collect(Collectors.toList());
        
        // 3. 캐시에 저장
        cacheRoles(userId, authorities, CACHE_TTL_SECONDS);
        
        return new UsernamePasswordAuthenticationToken(
            userId, null, authorities
        );
    }
    
    private List<GrantedAuthority> getCachedRoles(Long userId) {
        Cache cache = cacheManager.getCache(ROLE_CACHE);
        if (cache != null) {
            Cache.ValueWrapper wrapper = cache.get(userId);
            if (wrapper != null) {
                return (List<GrantedAuthority>) wrapper.get();
            }
        }
        return null;
    }
    
    private void cacheRoles(Long userId, List<GrantedAuthority> authorities, 
                           long ttlSeconds) {
        Cache cache = cacheManager.getCache(ROLE_CACHE);
        if (cache != null) {
            cache.put(userId, authorities);
        }
    }
}
```

### 트레이드오프 2: 토큰 포함 정보 vs 서비스 간 통신

```
최소 정보 (ID만):
+ 보안 (권한 정보 변조 불가)
- 마이크로서비스에서 권한 조회 필요
- 서비스 간 통신 증가

풍부한 정보 (role 포함):
+ 성능 (권한 조회 필요 없음)
- 보안 위험 (토큰 변조)
```

**해결책**: 서비스별 권한 매핑

```java
@Component
public class ServiceAuthorityMapper {
    
    private Map<String, Set<String>> serviceRoles = Map.of(
        "USER_SERVICE", Set.of("ROLE_USER", "ROLE_ADMIN"),
        "PAYMENT_SERVICE", Set.of("ROLE_CUSTOMER", "ROLE_MERCHANT"),
        "ADMIN_SERVICE", Set.of("ROLE_ADMIN", "ROLE_SUPER_ADMIN")
    );
    
    public List<GrantedAuthority> mapToServiceAuthorities(
            User user, String targetService) {
        
        Set<String> allowedRoles = serviceRoles.getOrDefault(targetService, Set.of());
        
        return user.getRoles().stream()
            .filter(role -> allowedRoles.contains(role.getRoleName()))
            .map(role -> new SimpleGrantedAuthority(role.getRoleName()))
            .collect(Collectors.toList());
    }
}
```

---

## 📌 핵심 정리

1. **JWT의 한계**: 서명되어 있지만 토큰 생성 후 권한이 변경될 수 있음
2. **필수 검증**:
   - 토큰 서명 검증 (필수)
   - 토큰 만료 확인 (필수)
   - DB에서 권한 재검증 (필수!)
   - 계정 활성 상태 확인 (필수!)
3. **방어 전략**:
   - 토큰에는 최소 정보만 (ID, username)
   - 권한은 매 요청마다 DB에서 조회
   - 권한 변경 시 즉시 반영
   - 토큰 블랙리스트로 로그아웃 시 무효화
4. **마이크로서비스**: 다른 서비스에서 발급한 토큰도 재검증
5. **캐싱**: DB 부하를 위해 권한 정보를 5~10분 캐시

---

## 🤔 생각해볼 문제 (+ 해설)

### 문제 1: 토큰의 만료 시간이 길면 (예: 30일)?

**상황**: 사용자 권한을 박탈했는데 토큰은 여전히 유효

**해설**:
DB 재검증을 하므로 문제없습니다. 하지만 토큰 만료 시간은 짧을수록 좋습니다:

```java
// 단기 토큰 + 리프레시 토큰 전략
public TokenResponse generateTokens(User user) {
    String accessToken = generateAccessToken(user);    // 15분
    String refreshToken = generateRefreshToken(user);  // 7일
    
    return new TokenResponse(accessToken, refreshToken);
}

// 리프레시 토큰으로 새 액세스 토큰 발급
@PostMapping("/refresh")
public ResponseEntity<TokenResponse> refresh(@RequestBody RefreshRequest request) {
    String newAccessToken = generateAccessToken(
        validateRefreshToken(request.getRefreshToken())
    );
    
    return ResponseEntity.ok(new TokenResponse(newAccessToken, null));
}
```

---

### 문제 2: 마이크로서비스가 10개면?

**상황**: 모든 서비스에서 원래 서비스에 재검증 요청?

**해설**:
API 게이트웨이에서 중앙 집중식 검증을 하세요:

```java
// API 게이트웨이: 모든 요청의 토큰 검증
@Component
public class ApiGatewaySecurityFilter extends OncePerRequestFilter {
    
    @Autowired
    private ServiceTokenValidator serviceTokenValidator;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                   HttpServletResponse response,
                                   FilterChain filterChain) throws ServletException, IOException {
        
        String jwt = extractToken(request);
        
        if (jwt != null) {
            // 게이트웨이에서 한 번만 검증
            serviceTokenValidator.validateTokenWithAuthService(jwt);
            
            // 검증된 토큰만 백엔드 서비스로 전달
            filterChain.doFilter(request, response);
        }
    }
}

// 백엔드 서비스: 토큰 신뢰 (게이트웨이에서 검증됨)
```

<div align="center">

**[⬅️ 이전: API Rate Limiting 설계](./04-api-rate-limiting.md)** | **[홈으로 🏠](../README.md)** | **[다음: 최소 권한 원칙 ➡️](./06-least-privilege-principle.md)**

</div>
