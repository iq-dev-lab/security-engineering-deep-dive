# 02. 수평적 vs 수직적 권한 상승 — 같은 권한 내에서의 확장, 높은 권한으로의 점프

---

## 🎯 핵심 질문

**수평적 권한 상승 (Horizontal Privilege Escalation)**
: 같은 권한 레벨의 다른 사용자 데이터에 접근하는 공격

예) 일반 사용자 A가 일반 사용자 B의 마이페이지를 보거나, B의 개인정보를 수정하는 행위

**수직적 권한 상승 (Vertical Privilege Escalation)**
: 낮은 권한 사용자가 높은 권한의 기능을 무단으로 사용하는 공격

예) 일반 사용자가 숨겨진 `/admin/users/delete` 엔드포인트를 발견하여 다른 사용자를 삭제하거나, 자신의 역할을 `"role": "ADMIN"`으로 변경하는 행위

둘 다 인증(Authentication)은 통과했지만 인가(Authorization) 정책을 우회하는 취약점입니다.

---

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

### 실제 사고 사례 1: 수평적 권한 상승 — 국내 SNS 서비스 정보 유출
2020년 국내 SNS 서비스에서 `/api/users/{userId}/profile`이 현재 사용자가 조회하는 사용자의 소유권을 검증하지 않아, 공격자가 다른 사용자들의 **전화번호, 생년월일, 이메일**을 대량 수집한 사건이 발생했습니다. 본인 확인 과정에서 수집된 민감한 정보로 계정 탈취까지 이어졌습니다.

### 실제 사고 사례 2: 수직적 권한 상승 — 전자상거래 플랫폼 관리자 기능 무단 접근
한 프로덕트 관리자가 `/api/admin/discounts/apply` 엔드포인트가 실제로는 권한을 검증하지 않는다는 것을 발견하고, 임의로 95% 할인을 적용하여 **8시간 동안 2억 원의 손실**을 입혔습니다. 프론트엔드에는 관리자 메뉴가 없었지만, 백엔드 API 자체에는 권한 검증이 없었습니다.

### 실제 사고 사례 3: 역할 변조를 통한 수직적 권한 상승
금융 애플리케이션에서 JWT 토큰의 `"role": "USER"` 클레임을 클라이언트가 `"role": "MANAGER"`로 변경하여 송금 한도 제한을 우회하고 **대량 자금이체**를 수행한 사건이 있었습니다.

### 왜 위험한가?
- **기능 수준의 보안 실패**: 프론트엔드에서 메뉴를 숨겨도 백엔드 API가 보호되지 않으면 무의미
- **데이터 무결성 침해**: 수직 권한 상승으로 다른 사용자의 데이터를 임의로 수정 가능
- **내부자 위협**: 권한 분리가 없으면 내부 직원의 부정행위 감시 불가
- **감사 추적 어려움**: 접근 로그만으로는 권한을 보유했는지 판단 불가

---

## 😱 취약한 코드 (Before — 원리를 모를 때의 구현)

### 취약점 1: 수평적 권한 상승 — 마이페이지 정보 조회 및 수정

```java
// 취약한 사용자 관리 컨트롤러
@RestController
@RequestMapping("/api/users")
public class UserController {
    
    @Autowired
    private UserService userService;
    
    // 문제 1: 로그인한 사용자면 누구든 다른 사용자 정보 조회 가능
    @PreAuthorize("isAuthenticated()")
    @GetMapping("/{userId}")
    public ResponseEntity<UserDto> getUserProfile(@PathVariable Long userId) {
        User user = userService.findById(userId);
        // 현재 사용자가 userId 사용자의 소유자인지 확인하지 않음!
        return ResponseEntity.ok(new UserDto(user));
    }
    
    // 문제 2: 로그인한 사용자면 누구든 다른 사용자 정보 수정 가능
    @PreAuthorize("isAuthenticated()")
    @PutMapping("/{userId}")
    public ResponseEntity<UserDto> updateUserProfile(
            @PathVariable Long userId,
            @RequestBody UserUpdateRequest request) {
        
        User user = userService.findById(userId);
        user.setEmail(request.getEmail());
        user.setPhone(request.getPhone());
        user.setAddress(request.getAddress());
        
        return ResponseEntity.ok(new UserDto(userService.save(user)));
    }
}

// 취약한 서비스 계층
@Service
public class UserService {
    
    @Autowired
    private UserRepository userRepository;
    
    public User findById(Long userId) {
        // 소유권 검증 없이 직접 조회
        return userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException("User not found"));
    }
    
    public User save(User user) {
        return userRepository.save(user);
    }
}

// JPA 엔티티
@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(unique = true)
    private String username;
    
    @Column(unique = true)
    private String email;
    
    private String phone;
    private String address;
    private String password;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "role")
    private Role role;  // ROLE_USER, ROLE_MANAGER, ROLE_ADMIN
    
    // getter/setter...
}

enum Role {
    ROLE_USER, ROLE_MANAGER, ROLE_ADMIN
}
```

### 취약점 2: 수직적 권한 상승 — 숨겨진 관리자 API 무단 접근

```java
// 관리자 컨트롤러 — 프론트엔드에는 메뉴가 없지만 백엔드에 존재
@RestController
@RequestMapping("/api/admin/users")
public class AdminUserController {
    
    @Autowired
    private UserService userService;
    
    // 문제: 권한 검증이 없음!
    @GetMapping
    public ResponseEntity<List<UserDto>> getAllUsers() {
        List<User> users = userService.findAll();
        return ResponseEntity.ok(users.stream()
            .map(UserDto::new)
            .toList());
    }
    
    // 문제: 누구든 사용자 역할을 변경 가능
    @PutMapping("/{userId}/role")
    public ResponseEntity<UserDto> changeUserRole(
            @PathVariable Long userId,
            @RequestBody ChangeRoleRequest request) {
        
        User user = userService.findById(userId);
        user.setRole(Role.valueOf("ROLE_" + request.getRole().toUpperCase()));
        
        return ResponseEntity.ok(new UserDto(userService.save(user)));
    }
    
    // 문제: 누구든 사용자 삭제 가능
    @DeleteMapping("/{userId}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long userId) {
        userService.deleteById(userId);
        return ResponseEntity.noContent().build();
    }
}

@RestController
@RequestMapping("/api/admin/discounts")
public class AdminDiscountController {
    
    @Autowired
    private DiscountService discountService;
    
    // 문제: 할인율을 임의로 설정 가능
    @PostMapping
    public ResponseEntity<DiscountDto> createDiscount(
            @RequestBody DiscountCreateRequest request) {
        
        Discount discount = new Discount();
        discount.setPercentage(request.getPercentage());  // 95% 할인 가능!
        discount.setProductId(request.getProductId());
        discount.setStartDate(LocalDateTime.now());
        discount.setEndDate(LocalDateTime.now().plusHours(8));
        
        return ResponseEntity.ok(new DiscountDto(
            discountService.save(discount)
        ));
    }
}
```

### 취약점 3: JWT 클레임 변조를 통한 권한 상승

```java
// 취약한 JWT 검증 로직
@Component
public class JwtTokenProvider {
    
    private String secretKey = "my-secret-key";  // 너무 약함!
    
    // JWT 생성
    public String generateToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", user.getId());
        claims.put("username", user.getUsername());
        claims.put("role", user.getRole());  // 클라이언트가 변조 가능!
        
        return Jwts.builder()
            .setClaims(claims)
            .setSubject(user.getUsername())
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + 86400000))
            .signWith(SignatureAlgorithm.HS256, secretKey)
            .compact();
    }
    
    // 문제: 클라이언트가 전송한 JWT를 그냥 파싱하고, 'role' 클레임을 신뢰함
    public Authentication getAuthentication(String token) {
        Claims claims = Jwts.parser()
            .setSigningKey(secretKey)
            .parseClaimsJws(token)
            .getBody();
        
        String userId = claims.get("userId").toString();
        String role = claims.get("role").toString();  // 클라이언트가 변조한 값!
        
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(role));
        
        // SecurityContext에 클라이언트의 주장을 그대로 반영
        return new UsernamePasswordAuthenticationToken(userId, null, authorities);
    }
}

// 공격 시뮬레이션
public class TokenManipulationAttack {
    
    public static void main(String[] args) {
        // 1. 정상 토큰 획득 (USER 역할)
        String originalToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
        
        // 2. 토큰을 디코딩하면:
        // {
        //   "userId": "12345",
        //   "username": "attacker",
        //   "role": "ROLE_USER"
        // }
        
        // 3. 클라이언트가 'role'을 변조:
        String tamperedToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
        // {
        //   "userId": "12345",
        //   "username": "attacker",
        //   "role": "ROLE_ADMIN"  ← 변조!
        // }
        
        // 4. 변조된 토큰으로 관리자 API 접근
        // GET /api/admin/users → 성공! (권한 검증이 없음)
    }
}
```

### 공격자의 실제 공격 흐름

```bash
# 공격 1: 수평적 권한 상승 (마이페이지 정보 수정)
# 자신의 계정(ID=100)으로 로그인
TOKEN=$(curl -X POST http://localhost:8080/api/auth/login \
  -d '{"username":"attacker","password":"password"}' | jq -r '.token')

# 다른 사용자(ID=1)의 정보 조회
curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:8080/api/users/1

# 다른 사용자의 이메일 변경!
curl -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@evil.com"}' \
  http://localhost:8080/api/users/1

# 공격 2: 수직적 권한 상승 (숨겨진 관리자 API)
# 관리자 API는 프론트엔드에 없지만 백엔드 존재
curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:8080/api/admin/users

# 다른 사용자를 관리자로 승격
curl -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"ADMIN"}' \
  http://localhost:8080/api/admin/users/999

# 공격 3: 토큰 변조
# jwt.io에서 토큰 디코딩 후 클레임 수정:
# {"role": "ROLE_USER"} → {"role": "ROLE_ADMIN"}
# 서명은 유효하지만 권한 검증이 없으므로 관리자 권한 획득
```

---

## ✨ 방어 코드 (After — 공격 원리를 알고 설계한 구현)

### 방어 전략 1: 수평적 권한 상승 방어 — 소유권 검증

```java
// 개선된 사용자 관리 컨트롤러
@RestController
@RequestMapping("/api/users")
public class UserController {
    
    @Autowired
    private UserService userService;
    
    // 방어: 현재 사용자만 자신의 정보 조회 가능
    @PreAuthorize("isAuthenticated()")
    @GetMapping("/{userId}")
    public ResponseEntity<UserDto> getUserProfile(
            @PathVariable Long userId,
            @AuthenticationPrincipal CustomUserDetails userDetails) {
        
        Long currentUserId = userDetails.getUserId();
        
        // 자신의 정보가 아니면 조회 불가
        if (!currentUserId.equals(userId)) {
            throw new AccessDeniedException("You can only view your own profile");
        }
        
        User user = userService.findById(userId);
        return ResponseEntity.ok(new UserDto(user));
    }
    
    // 방어: 현재 사용자만 자신의 정보 수정 가능
    @PreAuthorize("isAuthenticated()")
    @PutMapping("/{userId}")
    public ResponseEntity<UserDto> updateUserProfile(
            @PathVariable Long userId,
            @RequestBody UserUpdateRequest request,
            @AuthenticationPrincipal CustomUserDetails userDetails) {
        
        Long currentUserId = userDetails.getUserId();
        
        if (!currentUserId.equals(userId)) {
            throw new AccessDeniedException("You can only modify your own profile");
        }
        
        User user = userService.findById(userId);
        
        // 사용자가 수정 가능한 필드만 업데이트
        user.setEmail(request.getEmail());
        user.setPhone(request.getPhone());
        user.setAddress(request.getAddress());
        
        // 역할(role)은 절대 변경 불가
        // user.setRole(...) ← 의도적으로 제거
        
        return ResponseEntity.ok(new UserDto(userService.save(user)));
    }
}
```

### 방어 전략 2: 수직적 권한 상승 방어 — 역할 기반 접근 제어

```java
// 개선된 관리자 컨트롤러 — 명시적 권한 검증
@RestController
@RequestMapping("/api/admin/users")
public class AdminUserController {
    
    @Autowired
    private UserService userService;
    
    @Autowired
    private AuditLog auditLog;
    
    // 방어 1: @PreAuthorize로 명시적 역할 검증
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping
    public ResponseEntity<Page<UserDto>> getAllUsers(
            @PageableDefault(size = 20) Pageable pageable,
            @AuthenticationPrincipal CustomUserDetails userDetails) {
        
        // 감시 로깅: 관리자 API 접근 기록
        auditLog.log("ADMIN_GET_ALL_USERS", userDetails.getUserId(), null);
        
        Page<User> users = userService.findAll(pageable);
        return ResponseEntity.ok(users.map(UserDto::new));
    }
    
    // 방어 2: 역할 변경 API — 엄격한 권한 검증
    @PreAuthorize("hasRole('SUPER_ADMIN')")  // ADMIN보다 높은 권한 필요
    @PutMapping("/{userId}/role")
    public ResponseEntity<UserDto> changeUserRole(
            @PathVariable Long userId,
            @RequestBody ChangeRoleRequest request,
            @AuthenticationPrincipal CustomUserDetails userDetails) {
        
        // 자신의 역할은 변경 불가
        if (userDetails.getUserId().equals(userId)) {
            throw new BusinessException("Cannot change your own role");
        }
        
        User user = userService.findById(userId);
        
        // 허용된 역할만 변경 가능
        Role newRole = Role.valueOf("ROLE_" + request.getRole().toUpperCase());
        if (!isValidRoleTransition(user.getRole(), newRole)) {
            throw new BusinessException("Invalid role transition");
        }
        
        // 감시 로깅
        auditLog.log("USER_ROLE_CHANGED", userDetails.getUserId(), 
                     String.format("Changed user %d from %s to %s", 
                                   userId, user.getRole(), newRole));
        
        user.setRole(newRole);
        return ResponseEntity.ok(new UserDto(userService.save(user)));
    }
    
    private boolean isValidRoleTransition(Role from, Role to) {
        // 역할 전이 규칙 정의: ADMIN이 USER를 MANAGER로는 변경 가능하지만
        // USER를 ADMIN으로는 변경 불가
        if (from == Role.ROLE_USER && to == Role.ROLE_MANAGER) {
            return true;
        }
        if (from == Role.ROLE_MANAGER && to == Role.ROLE_USER) {
            return true;
        }
        return false;
    }
    
    // 방어 3: 사용자 삭제 — 매우 엄격한 권한 검증
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    @DeleteMapping("/{userId}")
    public ResponseEntity<Void> deleteUser(
            @PathVariable Long userId,
            @RequestParam(required = true) String confirmationCode,
            @AuthenticationPrincipal CustomUserDetails userDetails) {
        
        // 자신을 삭제하려는 시도 방어
        if (userDetails.getUserId().equals(userId)) {
            throw new BusinessException("Cannot delete your own account");
        }
        
        // 추가 확인 코드 필요
        if (!verifyDeletionConfirmation(userId, confirmationCode)) {
            throw new BusinessException("Invalid confirmation code");
        }
        
        User user = userService.findById(userId);
        
        // 감시 로깅 (매우 자세함)
        auditLog.log("USER_DELETED", userDetails.getUserId(), 
                     String.format("Deleted user: %s (ID: %d, Email: %s)", 
                                   user.getUsername(), userId, user.getEmail()));
        
        userService.deleteById(userId);
        return ResponseEntity.noContent().build();
    }
    
    private boolean verifyDeletionConfirmation(Long userId, String code) {
        // 실제로는 외부 시스템이나 이메일 인증 통합
        return true;
    }
}

@RestController
@RequestMapping("/api/admin/discounts")
public class AdminDiscountController {
    
    @Autowired
    private DiscountService discountService;
    
    @Autowired
    private AuditLog auditLog;
    
    // 방어: 할인율 제한 및 권한 검증
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping
    public ResponseEntity<DiscountDto> createDiscount(
            @RequestBody DiscountCreateRequest request,
            @AuthenticationPrincipal CustomUserDetails userDetails) {
        
        // 할인율 상한선 설정: 50% 이상은 불가
        if (request.getPercentage() > 50) {
            throw new BusinessException("Discount percentage cannot exceed 50%");
        }
        
        // 할인 기간 제한: 최대 7일
        long days = ChronoUnit.DAYS.between(
            request.getStartDate(),
            request.getEndDate()
        );
        if (days > 7) {
            throw new BusinessException("Discount duration cannot exceed 7 days");
        }
        
        Discount discount = new Discount();
        discount.setPercentage(request.getPercentage());
        discount.setProductId(request.getProductId());
        discount.setStartDate(request.getStartDate());
        discount.setEndDate(request.getEndDate());
        discount.setCreatedBy(userDetails.getUserId());
        
        // 감시 로깅
        auditLog.log("DISCOUNT_CREATED", userDetails.getUserId(),
                     String.format("Created discount: %d%% for product %d",
                                   request.getPercentage(), request.getProductId()));
        
        return ResponseEntity.ok(new DiscountDto(
            discountService.save(discount)
        ));
    }
}
```

### 방어 전략 3: JWT 클레임 검증 — 서버 측 권한 재확인

```java
// 개선된 JWT 토큰 제공자
@Component
public class JwtTokenProvider {
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private RoleRepository roleRepository;
    
    @Value("${jwt.secret}")
    private String secretKey;
    
    @Value("${jwt.expiration}")
    private long validityInMilliseconds;
    
    // JWT 생성: 최소한의 정보만 포함
    public String generateToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", user.getId());
        claims.put("username", user.getUsername());
        // 주의: 'role'은 포함하지 않음. 서버에서 매번 조회
        
        return Jwts.builder()
            .setClaims(claims)
            .setSubject(user.getUsername())
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + validityInMilliseconds))
            .signWith(SignatureAlgorithm.HS512, secretKey)
            .compact();
    }
    
    // JWT 검증: 클레임을 신뢰하지 않고 서버에서 재확인
    public Authentication getAuthentication(String token) {
        Claims claims = Jwts.parser()
            .setSigningKey(secretKey)
            .parseClaimsJws(token)
            .getBody();
        
        Long userId = Long.valueOf(claims.get("userId").toString());
        String username = claims.getSubject();
        
        // 중요: 데이터베이스에서 사용자와 역할을 다시 조회
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException("User not found"));
        
        // 클라이언트가 보낸 토큰의 역할을 신뢰하지 않음
        // 대신 현재 데이터베이스의 역할 정보 사용
        List<GrantedAuthority> authorities = user.getRoles().stream()
            .map(role -> new SimpleGrantedAuthority(role.getRoleName()))
            .collect(Collectors.toList());
        
        // 추가 검증: 사용자 상태 확인
        if (!user.isEnabled()) {
            throw new DisabledException("User account is disabled");
        }
        
        if (user.isLocked()) {
            throw new LockedException("User account is locked");
        }
        
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
}

// 더 강력한 권한 검증: 메서드 보안 계층 추가
@Component
public class MethodSecurityEvaluator {
    
    @Autowired
    private UserRepository userRepository;
    
    // 메서드 호출 전에 권한 재확인
    public boolean hasPermission(Long userId, String resource, String action) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException("User not found"));
        
        // 데이터베이스의 최신 역할 정보로 검증
        return user.getRoles().stream()
            .anyMatch(role -> canPerformAction(role, resource, action));
    }
    
    private boolean canPerformAction(Role role, String resource, String action) {
        // 역할별 리소스 접근 제어 정의
        if (role.getRoleName().equals("ROLE_ADMIN")) {
            return true;  // 관리자는 모든 리소스에 접근 가능
        }
        
        if (role.getRoleName().equals("ROLE_USER")) {
            // 일반 사용자는 읽기만 가능
            return action.equals("READ");
        }
        
        return false;
    }
}
```

### 방어 전략 4: 커스텀 권한 검증 Bean

```java
// 선택적: 메서드 레벨 권한 검증
@Component("ownerChecker")
public class OwnershipChecker {
    
    @Autowired
    private UserRepository userRepository;
    
    public boolean isOwner(Long userId, Long currentUserId) {
        return userId.equals(currentUserId);
    }
    
    public boolean isAdminOrOwner(Long userId, Long currentUserId) {
        User currentUser = userRepository.findById(currentUserId)
            .orElseThrow(() -> new UserNotFoundException("User not found"));
        
        return currentUser.getRoles().stream()
                   .anyMatch(role -> role.getRoleName().equals("ROLE_ADMIN"))
               || userId.equals(currentUserId);
    }
}

// 사용 예
@RestController
@RequestMapping("/api/users")
public class UserController {
    
    // SpEL (Spring Expression Language)로 복잡한 권한 규칙 표현
    @PreAuthorize("@ownerChecker.isAdminOrOwner(#userId, authentication.principal.userId)")
    @GetMapping("/{userId}")
    public ResponseEntity<UserDto> getUserProfile(@PathVariable Long userId) {
        // ...
    }
}
```

---

## 🔬 공격 원리 분석 (공격자 관점의 내부 동작)

### 수평적 권한 상승의 공격 원리

```
Step 1: 정상 요청 분석
┌─────────────────────────────────────────────┐
│ GET /api/users/100                          │
│ Authorization: Bearer user_100_token        │
│ → Response: {"id": 100, ...}                │
└─────────────────────────────────────────────┘

Step 2: 다른 사용자 요청 시도
┌─────────────────────────────────────────────┐
│ GET /api/users/101                          │
│ Authorization: Bearer user_100_token        │
│ → Response: {"id": 101, ...} ← 소유권 검증 없음!
└─────────────────────────────────────────────┘

Step 3: 자동화된 데이터 수집
┌─────────────────────────────────────────────┐
│ for id in range(1, 100000):                 │
│     GET /api/users/{id}                     │
│ → 모든 사용자의 정보 수집 가능!              │
└─────────────────────────────────────────────┘

Step 4: 데이터 조작 (쓰기 권한까지 없으면)
┌─────────────────────────────────────────────┐
│ PUT /api/users/101                          │
│ {"email": "attacker@evil.com"}              │
│ → 다른 사용자의 이메일 변경!                 │
└─────────────────────────────────────────────┘
```

### 수직적 권한 상승의 공격 원리

```
Step 1: API 엔드포인트 발견
┌─────────────────────────────────────────────┐
│ 프론트엔드 분석 또는 역공학:                 │
│ - /api/admin 경로 패턴 추측                  │
│ - /swagger-ui.html 또는 /api/docs 확인      │
│ - 프록시 도구로 모든 요청 모니터링           │
└─────────────────────────────────────────────┘

Step 2: 권한 검증 부재 확인
┌─────────────────────────────────────────────┐
│ GET /api/admin/users                        │
│ Authorization: Bearer user_100_token        │
│ (ROLE_USER이지만)                           │
│ → Response: 200 OK ← 권한 검증 없음!        │
└─────────────────────────────────────────────┘

Step 3: 민감한 작업 수행
┌─────────────────────────────────────────────┐
│ PUT /api/admin/users/1/role                 │
│ {"role": "ADMIN"}                           │
│ → 자신을 관리자로 승격!                      │
│                                             │
│ 또는:                                        │
│ PUT /api/users/100/role                     │
│ {"role": "ADMIN"}                           │
│ → 자신의 역할 직접 변경!                     │
└─────────────────────────────────────────────┘
```

### JWT 클레임 변조 공격

```
원본 토큰:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJ1c2VySWQiOiIxMDAiLCJ1c2VybmFtZSI6ImF0dGFja2VyIiwicm9sZSI6IlJPTEVfVVNFUiJ9.
sig...

Step 1: 토큰 디코딩
┌──────────────────────────────────────────┐
│ Header: {                                │
│   "alg": "HS256",                        │
│   "typ": "JWT"                           │
│ }                                        │
│                                          │
│ Payload: {                               │
│   "userId": "100",                       │
│   "username": "attacker",                │
│   "role": "ROLE_USER"  ← 변조 대상      │
│ }                                        │
└──────────────────────────────────────────┘

Step 2: 클레임 변조 (클라이언트에서)
┌──────────────────────────────────────────┐
│ Payload 수정:                            │
│ {                                        │
│   "userId": "100",                       │
│   "username": "attacker",                │
│   "role": "ROLE_ADMIN"  ← 변조됨!       │
│ }                                        │
└──────────────────────────────────────────┘

Step 3: 새 토큰 생성 및 사용
┌──────────────────────────────────────────┐
│ 변조된 토큰으로 관리자 API 접근            │
│ → 서버가 'role' 클레임을 신뢰하면         │
│   권한 상승 성공!                         │
└──────────────────────────────────────────┘

실제 공격 도구: jwt.io, Postman, Python jwt 라이브러리
```

---

## 💻 실전 실험 (취약점 재현 → 공격 → 방어 검증)

### 실험 1: 수평적 권한 상승 테스트

```java
@SpringBootTest
@AutoConfigureMockMvc
public class HorizontalPrivilegeEscalationTest {
    
    @Autowired
    private MockMvc mockMvc;
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private JwtTokenProvider tokenProvider;
    
    private String user1Token;
    private String user2Token;
    
    @Before
    public void setup() {
        // 테스트 사용자 생성
        User user1 = new User();
        user1.setId(1L);
        user1.setUsername("user1");
        user1.setEmail("user1@example.com");
        user1.setRole(Role.ROLE_USER);
        userRepository.save(user1);
        
        User user2 = new User();
        user2.setId(2L);
        user2.setUsername("user2");
        user2.setEmail("user2@example.com");
        user2.setRole(Role.ROLE_USER);
        userRepository.save(user2);
        
        user1Token = tokenProvider.generateToken(user1);
        user2Token = tokenProvider.generateToken(user2);
    }
    
    @Test
    public void testHorizontalEscalation_Vulnerable_ShouldSucceed() throws Exception {
        // 취약한 코드: user1이 user2의 정보 조회 가능
        mockMvc.perform(get("/api/users/2")
                .header("Authorization", "Bearer " + user1Token))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.email").value("user2@example.com"));
    }
    
    @Test
    public void testHorizontalEscalation_Defended_ShouldDeny() throws Exception {
        // 방어된 코드: user1이 user2의 정보 조회 거부
        mockMvc.perform(get("/api/users/2")
                .header("Authorization", "Bearer " + user1Token))
            .andExpect(status().isForbidden());
    }
    
    @Test
    public void testHorizontalEscalation_Defended_OwnProfile_ShouldSucceed() throws Exception {
        // 방어된 코드: user1이 자신의 정보 조회 가능
        mockMvc.perform(get("/api/users/1")
                .header("Authorization", "Bearer " + user1Token))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.email").value("user1@example.com"));
    }
}
```

### 실험 2: 수직적 권한 상승 테스트

```java
@SpringBootTest
@AutoConfigureMockMvc
public class VerticalPrivilegeEscalationTest {
    
    @Autowired
    private MockMvc mockMvc;
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private JwtTokenProvider tokenProvider;
    
    private String userToken;
    private String adminToken;
    
    @Before
    public void setup() {
        User user = new User();
        user.setId(1L);
        user.setUsername("user");
        user.setRole(Role.ROLE_USER);
        userRepository.save(user);
        
        User admin = new User();
        admin.setId(2L);
        admin.setUsername("admin");
        admin.setRole(Role.ROLE_ADMIN);
        userRepository.save(admin);
        
        userToken = tokenProvider.generateToken(user);
        adminToken = tokenProvider.generateToken(admin);
    }
    
    @Test
    public void testVerticalEscalation_Vulnerable_ShouldSucceed() throws Exception {
        // 취약한 코드: 일반 사용자가 관리자 API 접근 가능
        mockMvc.perform(get("/api/admin/users")
                .header("Authorization", "Bearer " + userToken))
            .andExpect(status().isOk());
    }
    
    @Test
    public void testVerticalEscalation_Defended_ShouldDeny() throws Exception {
        // 방어된 코드: 일반 사용자는 관리자 API 접근 거부
        mockMvc.perform(get("/api/admin/users")
                .header("Authorization", "Bearer " + userToken))
            .andExpect(status().isForbidden());
    }
    
    @Test
    public void testVerticalEscalation_Defended_AdminOnly_ShouldSucceed() throws Exception {
        // 방어된 코드: 관리자만 접근 가능
        mockMvc.perform(get("/api/admin/users")
                .header("Authorization", "Bearer " + adminToken))
            .andExpect(status().isOk());
    }
    
    @Test
    public void testVerticalEscalation_RoleChange_Vulnerable() throws Exception {
        // 취약한 코드: 일반 사용자가 자신의 역할 변경 가능
        mockMvc.perform(put("/api/users/1/role")
                .header("Authorization", "Bearer " + userToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"role\":\"ADMIN\"}"))
            .andExpect(status().isOk());
    }
    
    @Test
    public void testVerticalEscalation_RoleChange_Defended() throws Exception {
        // 방어된 코드: 일반 사용자는 자신의 역할 변경 불가
        mockMvc.perform(put("/api/users/1/role")
                .header("Authorization", "Bearer " + userToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"role\":\"ADMIN\"}"))
            .andExpect(status().isForbidden());
    }
}
```

### 실험 3: JWT 클레임 변조 테스트

```java
@SpringBootTest
public class JwtClaimManipulationTest {
    
    @Autowired
    private JwtTokenProvider tokenProvider;
    
    @Autowired
    private UserRepository userRepository;
    
    @Test
    public void testJwtManipulation_Vulnerable_RoleEscalation() throws Exception {
        // 취약한 코드: 클라이언트가 role 클레임 변조
        
        User user = new User();
        user.setId(1L);
        user.setUsername("user");
        user.setRole(Role.ROLE_USER);
        userRepository.save(user);
        
        String originalToken = tokenProvider.generateToken(user);
        
        // 토큰을 분석하고 role 클레임 변조 (jwt.io 사용)
        String tamperedToken = createTamperedToken(originalToken, "ROLE_ADMIN");
        
        // 취약한 서버는 변조된 role을 신뢰
        Authentication auth = tokenProvider.getAuthentication(tamperedToken);
        assertTrue(auth.getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN")));
    }
    
    @Test
    public void testJwtManipulation_Defended_ServerRevalidation() throws Exception {
        // 방어된 코드: 서버가 토큰의 role을 신뢰하지 않고 DB 재조회
        
        User user = new User();
        user.setId(1L);
        user.setUsername("user");
        user.setRole(Role.ROLE_USER);
        userRepository.save(user);
        
        String originalToken = tokenProvider.generateToken(user);
        
        // 토큰 변조 시도
        String tamperedToken = createTamperedToken(originalToken, "ROLE_ADMIN");
        
        // 방어된 서버는 DB에서 사용자 정보를 다시 조회
        // 따라서 변조된 role이 아닌 DB의 role (ROLE_USER) 사용
        Authentication auth = tokenProvider.getAuthentication(tamperedToken);
        
        // 변조된 role이 아닌 실제 role 사용됨
        assertTrue(auth.getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().equals("ROLE_USER")));
    }
    
    private String createTamperedToken(String originalToken, String newRole) {
        // jwt.io 시뮬레이션
        String[] parts = originalToken.split("\\.");
        String payload = new String(Base64.getDecoder().decode(parts[1]));
        
        // 클라이언트가 role 수정
        String tamperedPayload = payload.replace("ROLE_USER", newRole);
        
        // 서명은 유효하지만 내용은 변조됨
        return parts[0] + "." + 
               Base64.getEncoder().encodeToString(tamperedPayload.getBytes()) +
               "." + parts[2];
    }
}
```

---

## 📊 공격 성공 조건 vs 방어 성공 조건 비교

| 구분 | 수평적 권한 상승 (공격 성공) | 수평적 권한 상승 (방어 성공) |
|------|---------------------------|---------------------------|
| **인증** | 유효한 토큰 | 유효한 토큰 |
| **리소스 ID 접근** | /api/users/{otherId} | /api/users/{otherId} |
| **검증** | 없음 | currentUserId == pathVariable |
| **응답** | 200 OK + 데이터 | 403 Forbidden |
| **피해** | 모든 사용자 정보 노출 | 제한적 |

| 구분 | 수직적 권한 상승 (공격 성공) | 수직적 권한 상승 (방어 성공) |
|------|---------------------------|---------------------------|
| **API 발견** | /api/admin 경로 추측 | 동일 |
| **권한 검증** | @PreAuthorize 없음 | @PreAuthorize("hasRole('ADMIN')") |
| **DB 재검증** | 토큰만 신뢰 | 토큰 + DB 권한 재확인 |
| **응답** | 200 OK + 관리자 기능 | 403 Forbidden |

---

## ⚖️ 트레이드오프 (보안 강화 vs 사용성/성능)

### 트레이드오프 1: 매번 DB 조회 vs 성능

```java
// 매번 권한 재검증 (보안)
@PreAuthorize("isAuthenticated()")
public void adminOperation() {
    User user = userRepository.findById(userId);  // 매번 조회
    if (!user.hasRole("ADMIN")) {
        throw new AccessDeniedException();
    }
}

// 토큰만 신뢰 (성능)
@PreAuthorize("hasRole('ADMIN')")  // 토큰의 role만 검증
public void adminOperation() {
    // ...
}

// 해결책: 캐싱 + 주기적 무효화
@Cacheable(value = "userRoles", key = "#userId", 
           cacheManager = "5minuteTTLCacheManager")
public List<Role> getUserRoles(Long userId) {
    return userRepository.findById(userId).get().getRoles();
}
```

### 트레이드오프 2: 엄격한 권한 계층 vs 유연성

```java
// 너무 엄격한 권한 (보안)
@PreAuthorize("hasRole('SUPER_ADMIN')")  // ADMIN도 접근 불가
public void deleteUser(Long userId) {
    // ...
}

// 너무 유연한 권한 (편리하지만 위험)
@PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'SUPPORT')")
public void deleteUser(Long userId) {
    // 많은 사용자가 삭제 권한 보유
}

// 균형: 역할별 세부 권한 정의
@PreAuthorize("hasRole('ADMIN')")
@PostAuthorize("hasPermission(returnObject, 'DELETE')")
public User deleteUser(Long userId) {
    // ...
}
```

### 트레이드오프 3: 역할 변경 감시 vs 프라이버시

```java
// 과도한 로깅 (프라이버시 침해)
auditLog.log("USER_LOGIN", userId, ipAddress, userAgent, etc...);

// 최소 로깅 (감시 불가)
// 로깅 없음

// 균형: 민감한 작업만 로깅
if (operationType == OperationType.ROLE_CHANGE || 
    operationType == OperationType.DATA_DELETE) {
    auditLog.log(operationType, userId, affectedResource);
}
```

---

## 📌 핵심 정리

1. **수평적 권한 상승**: 같은 권한의 다른 사용자 데이터 접근
   - 방어: `currentUserId == pathVariable` 검증
   
2. **수직적 권한 상승**: 낮은 권한이 높은 권한 기능 접근
   - 방어: `@PreAuthorize("hasRole(...)")` + DB 재검증
   
3. **JWT 클레임 변조**: 토큰의 권한 정보를 클라이언트가 변경
   - 방어: 서버에서 매번 DB에서 권한 정보 재조회
   
4. **Spring Security 활용**:
   - `@PreAuthorize`: 메서드 호출 전 권한 검증
   - `@PostAuthorize`: 메서드 호출 후 반환값 검증
   - Method Security: SpEL로 복잡한 규칙 표현
   
5. **감시 로깅**: 역할 변경, 삭제 등 민감한 작업은 반드시 기록

---

## 🤔 생각해볼 문제 (+ 해설)

### 문제 1: API 버전이 여러 개일 때 권한 검증은?

**상황**: `/api/v1/admin/users`와 `/api/v2/admin/users` 동시 운영

**해설**:
두 버전 모두에 동일한 권한 검증이 필요합니다. 한 버전에만 검증이 있으면 다른 버전으로 우회 가능합니다.

```java
// 각 버전마다 권한 검증 필수
@RestController
@RequestMapping("/api/v1/admin")
public class AdminControllerV1 {
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/users")
    public List<UserDto> getUsers() { ... }
}

@RestController
@RequestMapping("/api/v2/admin")
public class AdminControllerV2 {
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/users")
    public Page<UserDto> getUsers(Pageable pageable) { ... }
}
```

---

### 문제 2: 비활성화된 계정도 토큰이 유효하면 접근 가능한가?

**상황**: 사용자 계정이 비활성화되었지만 기존 JWT 토큰이 아직 유효

**해설**:
DB 재검증 로직에서 계정 상태를 확인해야 합니다:

```java
public Authentication getAuthentication(String token) {
    Claims claims = Jwts.parser()
        .setSigningKey(secretKey)
        .parseClaimsJws(token)
        .getBody();
    
    Long userId = Long.valueOf(claims.get("userId").toString());
    User user = userRepository.findById(userId)
        .orElseThrow(() -> new UserNotFoundException("User not found"));
    
    // 추가 검증: 계정 상태 확인
    if (!user.isEnabled()) {
        throw new DisabledException("User account is disabled");
    }
    
    if (user.isLocked()) {
        throw new LockedException("User account is locked");
    }
    
    // ...
}
```

---

### 문제 3: 관리자도 모든 권한이 필요한가?

**상황**: 관리자 A가 관리자 B의 계정을 삭제할 수 있는가?

**해설**:
자신을 제외한 다른 관리자도 삭제할 수 있으려면, 더 높은 권한(SUPER_ADMIN)이 필요합니다:

```java
@PreAuthorize("hasRole('SUPER_ADMIN')")
public void deleteAdmin(Long adminId) {
    if (adminId.equals(getCurrentUserId())) {
        throw new BusinessException("Cannot delete yourself");
    }
    // ...
}
```

<div align="center">

**[⬅️ 이전: IDOR — 소유권 검증 없는 API의 위험](./01-idor-ownership-check.md)** | **[홈으로 🏠](../README.md)** | **[다음: Mass Assignment ➡️](./03-mass-assignment.md)**

</div>
