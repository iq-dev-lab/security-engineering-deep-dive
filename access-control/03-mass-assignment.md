# 03. Mass Assignment (매스 어사인먼트) — JSON 요청 필드 자동 매핑의 위험

---

## 🎯 핵심 질문

공격자가 다음과 같은 JSON 요청을 보낸다면?

```json
{
  "username": "attacker",
  "email": "attacker@example.com",
  "role": "ADMIN",
  "isAdmin": true,
  "accountBalance": 1000000
}
```

API가 단순히 모든 필드를 엔티티에 매핑하면, 공격자는 의도하지 않은 필드(role, accountBalance 등)까지 **변경할 수 있습니다**. 이것이 **Mass Assignment** 취약점입니다.

프론트엔드에서는 사용자가 "username"과 "email"만 변경할 수 있도록 UI를 제한했더라도, **API 요청을 직접 조작하면 "role"이나 "accountBalance" 필드도 변경 가능**합니다.

---

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

### 실제 사고 사례 1: Rails 매스 어사인먼트 취약점 (GitHub 침입 사건)
2012년 GitHub이 Rails의 매스 어사인먼트 취약점을 악용한 공격을 받았습니다. 공격자가 다음과 같은 요청을 보냈습니다:

```
POST /users/1
{
  "user[login]": "attacker",
  "user[admin]": true  # ← 프론트엔드 UI에는 없는 필드!
}
```

결과적으로 **일반 사용자가 자신의 계정을 관리자로 승격**할 수 있었습니다.

### 실제 사고 사례 2: 국내 이커머스 플랫폼 가격 변조
한 쇼핑몰의 상품 업데이트 API가 다음을 허용했습니다:

```json
{
  "name": "Product Name",
  "description": "...",
  "price": 50000,
  "cost": 5000        // ← 원가 정보!
}
```

원가 정보를 조회한 공격자는 **각 제품의 마진율을 분석**하고, 또한 비용 정보를 수정하여 **인벤토리 재무 정보를 왜곡**했습니다.

### 실제 사고 사례 3: 금융 애플리케이션 계정 잔액 변조
결제 API가 다음 필드를 모두 수락했습니다:

```json
{
  "transactionId": "tx_123",
  "amount": 10000,
  "accountId": "acc_456",
  "status": "COMPLETED",           // ← 클라이언트가 설정!
  "balance": 5000000               // ← 잔액 직접 설정!
}
```

공격자는 `"status": "COMPLETED"`와 `"balance"`를 직접 설정하여 **거래를 승인하고 잔액을 증가**시킬 수 있었습니다.

### 왜 위험한가?
- **권한 상승**: 일반 사용자가 관리자 권한을 자신에게 부여
- **데이터 무결성 침해**: 가격, 잔액, 상태 등 중요 필드 변조
- **재정적 손실**: 할인가로 대량 구매, 잔액 증가
- **감시 우회**: 서버 로그에는 정상 요청처럼 기록되어 탐지 어려움

---

## 😱 취약한 코드 (Before — 원리를 모를 때의 구현)

### 취약점 1: Jackson @JsonAnySetter로 모든 필드 자동 매핑

```java
// 취약한 사용자 엔티티
@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String username;
    private String email;
    private String phone;
    
    @Enumerated(EnumType.STRING)
    private Role role;  // ROLE_USER, ROLE_ADMIN
    
    private BigDecimal accountBalance;
    private boolean isAdmin;
    private boolean isSuperAdmin;
    
    // getter/setter... (모두 노출됨!)
}

// 취약한 요청 DTO
public class UserUpdateRequest {
    private String username;
    private String email;
    private String phone;
    private String role;  // ← 위험!
    private BigDecimal accountBalance;  // ← 위험!
    private boolean isAdmin;  // ← 위험!
    
    // Jackson이 자동으로 JSON의 모든 필드를 setter로 매핑
}

// 취약한 컨트롤러
@RestController
@RequestMapping("/api/users")
public class UserController {
    
    @Autowired
    private UserRepository userRepository;
    
    @PutMapping("/{userId}")
    public ResponseEntity<UserDto> updateUser(
            @PathVariable Long userId,
            @RequestBody UserUpdateRequest request,  // 모든 필드가 매핑됨!
            @AuthenticationPrincipal CustomUserDetails userDetails) {
        
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException("User not found"));
        
        // 문제: request의 모든 필드를 user에 매핑
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPhone(request.getPhone());
        
        // 문제: 다음 필드들도 매핑되어 위험!
        if (request.getRole() != null) {
            user.setRole(Role.valueOf("ROLE_" + request.getRole().toUpperCase()));
        }
        
        if (request.getAccountBalance() != null) {
            user.setAccountBalance(request.getAccountBalance());
        }
        
        if (request.isAdmin()) {
            user.setAdmin(true);
        }
        
        return ResponseEntity.ok(new UserDto(
            userRepository.save(user)
        ));
    }
}

// 공격자의 요청
POST /api/users/100
{
  "username": "attacker",
  "email": "attacker@example.com",
  "phone": "010-0000-0000",
  "role": "ADMIN",              // ← 추가: 자신을 관리자로!
  "accountBalance": 9999999,    // ← 추가: 잔액 증가!
  "isAdmin": true               // ← 추가: 관리자 플래그!
}

// 결과: 모든 필드가 변경됨! (역할 상승 + 재무 정보 변조)
```

### 취약점 2: 상품 업데이트 API에서의 Mass Assignment

```java
// 취약한 상품 엔티티
@Entity
@Table(name = "products")
public class Product {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String name;
    private String description;
    private BigDecimal price;  // 판매가
    private BigDecimal cost;   // ← 원가 (비공개 정보!)
    private int stock;         // ← 재고
    private boolean isPublished;
    private LocalDateTime publishedAt;
    
    // getter/setter...
}

// 취약한 상품 업데이트 요청 DTO
public class ProductUpdateRequest {
    private String name;
    private String description;
    private BigDecimal price;
    private BigDecimal cost;        // ← 위험! 원가 정보
    private int stock;              // ← 위험! 재고
    private boolean isPublished;    // ← 위험!
    
    // getter/setter...
}

// 취약한 상품 컨트롤러
@RestController
@RequestMapping("/api/products")
public class ProductController {
    
    @Autowired
    private ProductRepository productRepository;
    
    @PutMapping("/{productId}")
    public ResponseEntity<ProductDto> updateProduct(
            @PathVariable Long productId,
            @RequestBody ProductUpdateRequest request) {
        
        Product product = productRepository.findById(productId)
            .orElseThrow(() -> new ProductNotFoundException("Product not found"));
        
        // 문제: 모든 필드를 업데이트
        product.setName(request.getName());
        product.setDescription(request.getDescription());
        product.setPrice(request.getPrice());
        
        // 위험한 필드들도 업데이트됨!
        product.setCost(request.getCost());      // 원가 공개!
        product.setStock(request.getStock());    // 재고 변조!
        product.setPublished(request.isPublished());  // 공개 상태 변경!
        
        return ResponseEntity.ok(new ProductDto(
            productRepository.save(product)
        ));
    }
}

// 공격자의 요청 1: 원가 정보 수집
GET /api/products/123
# 응답에 cost 필드 포함

// 공격자의 요청 2: 재고 변조
PUT /api/products/123
{
  "name": "Product Name",
  "description": "...",
  "price": 50000,
  "cost": 1000,      // ← 변조: 실제로는 10000
  "stock": 999999    // ← 변조: 무제한 재고!
}
```

### 취약점 3: Spring Data JPA의 자동 매핑

```java
// 취약한 패턴: Spring Data의 save() 메서드
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    // 추가 메서드 정의 없음
}

@Service
public class UserService {
    
    @Autowired
    private UserRepository userRepository;
    
    // 취약한 구현
    public User updateUser(UserUpdateRequest request) {
        User user = userRepository.findById(request.getId()).orElseThrow();
        
        // 모든 필드를 복사 (BeanUtils.copyProperties)
        BeanUtils.copyProperties(request, user);
        
        return userRepository.save(user);  // 모든 필드 변경 반영!
    }
}

// 또는 더 위험한 패턴:
@PutMapping("/{userId}")
public ResponseEntity<User> updateUser(
        @PathVariable Long userId,
        @RequestBody User user) {
    
    user.setId(userId);
    return ResponseEntity.ok(userRepository.save(user));  // 엔티티 직접 받음!
}
```

---

## ✨ 방어 코드 (After — 공격 원리를 알고 설계한 구현)

### 방어 전략 1: 화이트리스트 DTO 패턴 (Request와 Entity 분리)

```java
// 전략 1-1: 명시적으로 허용된 필드만 DTO에 포함
// → 프론트엔드에서 변경 가능한 필드만 포함
@Data
@NoArgsConstructor
public class UserUpdateRequest {
    
    @NotBlank(message = "Username is required")
    private String username;
    
    @Email(message = "Email must be valid")
    private String email;
    
    @Pattern(regexp = "^01[0-9]-[0-9]{3,4}-[0-9]{4}$", 
             message = "Phone format is invalid")
    private String phone;
    
    // 주의: role, accountBalance, isAdmin 필드는 포함하지 않음!
    // 이들은 별도의 관리자 API에서만 변경 가능
}

// Entity는 더 많은 필드를 가지지만, DTO와는 분리됨
@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String username;
    private String email;
    private String phone;
    
    @Enumerated(EnumType.STRING)
    private Role role;  // DTO에는 없음
    
    private BigDecimal accountBalance;  // DTO에는 없음
    private boolean isAdmin;  // DTO에는 없음
    
    // getter/setter...
}

// 응답 DTO: 사용자에게 노출할 필드만
@Data
@NoArgsConstructor
public class UserDto {
    private Long id;
    private String username;
    private String email;
    private String phone;
    private String role;  // 읽기만 가능
    
    // accountBalance, isAdmin은 노출하지 않음!
    
    public UserDto(User user) {
        this.id = user.getId();
        this.username = user.getUsername();
        this.email = user.getEmail();
        this.phone = user.getPhone();
        this.role = user.getRole().name();
    }
}

// 개선된 컨트롤러
@RestController
@RequestMapping("/api/users")
public class UserController {
    
    @Autowired
    private UserService userService;
    
    @Autowired
    private UserMapper userMapper;
    
    @PutMapping("/{userId}")
    public ResponseEntity<UserDto> updateUser(
            @PathVariable Long userId,
            @RequestBody UserUpdateRequest request,  // DTO: 안전한 필드만
            @AuthenticationPrincipal CustomUserDetails userDetails) {
        
        // 소유권 검증
        if (!userDetails.getUserId().equals(userId)) {
            throw new AccessDeniedException("You can only modify your own profile");
        }
        
        // 서비스에 DTO 전달 (Entity가 아님!)
        User updatedUser = userService.updateUser(userId, request);
        
        return ResponseEntity.ok(new UserDto(updatedUser));
    }
}

// 서비스: DTO에서 Entity로의 안전한 변환
@Service
public class UserService {
    
    @Autowired
    private UserRepository userRepository;
    
    public User updateUser(Long userId, UserUpdateRequest request) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException("User not found"));
        
        // 명시적으로 허용된 필드만 업데이트
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPhone(request.getPhone());
        
        // 다른 필드(role, accountBalance 등)는 변경하지 않음
        
        return userRepository.save(user);
    }
}
```

### 방어 전략 2: Jackson @JsonProperty & @JsonIgnore 어노테이션

```java
// 전략 2-1: 읽기 전용 필드 지정
@Entity
@Table(name = "users")
@JsonIgnoreProperties(ignoreUnknown = true)  // 알려지지 않은 필드 무시
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String username;
    private String email;
    
    // 쓰기 금지: 읽기만 가능
    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    @Enumerated(EnumType.STRING)
    private Role role;
    
    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    private BigDecimal accountBalance;
    
    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    private boolean isAdmin;
    
    // 완전히 무시: JSON에 포함되지 않음
    @JsonIgnore
    private String internalNotes;
    
    @JsonIgnore
    private LocalDateTime lastLoginIp;
    
    // getter/setter...
}

// 전략 2-2: 요청 DTO에서 명시적으로 필드 제외
@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class UserUpdateRequest {
    
    private String username;
    private String email;
    private String phone;
    
    // 이 필드들은 DTO에 없으므로 변경 불가
    // - role
    // - accountBalance
    // - isAdmin
}

// 테스트: Jackson이 제외된 필드를 무시하는지 확인
@SpringBootTest
public class JsonPropertyTest {
    
    @Autowired
    private ObjectMapper objectMapper;
    
    @Test
    public void testJsonPropertyReadOnly() throws Exception {
        String json = """
            {
              "username": "attacker",
              "email": "attacker@example.com",
              "role": "ADMIN",
              "isAdmin": true
            }
            """;
        
        User user = objectMapper.readValue(json, User.class);
        
        // role과 isAdmin은 READ_ONLY이므로 무시됨
        assertEquals("attacker", user.getUsername());
        assertNotEquals(Role.ROLE_ADMIN, user.getRole());  // 변경되지 않음
        assertFalse(user.isAdmin());  // 변경되지 않음
    }
}
```

### 방어 전략 3: MapStruct를 이용한 명시적 매핑

```java
// MapStruct 의존성 추가
// <dependency>
//     <groupId>org.mapstruct</groupId>
//     <artifactId>mapstruct</artifactId>
//     <version>1.5.5.Final</version>
// </dependency>

// 매퍼 인터페이스: 명시적 필드 매핑
@Mapper(componentModel = "spring")
public interface UserMapper {
    
    // UserUpdateRequest → User: 명시적으로 정의된 필드만 매핑
    @Mapping(source = "username", target = "username")
    @Mapping(source = "email", target = "email")
    @Mapping(source = "phone", target = "phone")
    // role, accountBalance는 매핑하지 않음!
    void updateUserFromRequest(UserUpdateRequest request, @MappingTarget User user);
    
    // User → UserDto
    @Mapping(source = "id", target = "id")
    @Mapping(source = "username", target = "username")
    @Mapping(source = "email", target = "email")
    @Mapping(source = "role", target = "role")
    // accountBalance는 노출하지 않음!
    UserDto userToDto(User user);
    
    // 상품 업데이트의 안전한 매핑
    @Mapping(source = "name", target = "name")
    @Mapping(source = "description", target = "description")
    @Mapping(source = "price", target = "price")
    // cost와 stock은 매핑하지 않음!
    void updateProductFromRequest(ProductUpdateRequest request, @MappingTarget Product product);
}

// 서비스에서 매퍼 사용
@Service
public class UserService {
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private UserMapper userMapper;
    
    public User updateUser(Long userId, UserUpdateRequest request) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException("User not found"));
        
        // 매퍼가 명시적 매핑만 수행 (안전!)
        userMapper.updateUserFromRequest(request, user);
        
        return userRepository.save(user);
    }
}

// 컨트롤러
@RestController
@RequestMapping("/api/users")
public class UserController {
    
    @Autowired
    private UserService userService;
    
    @Autowired
    private UserMapper userMapper;
    
    @PutMapping("/{userId}")
    public ResponseEntity<UserDto> updateUser(
            @PathVariable Long userId,
            @RequestBody UserUpdateRequest request) {
        
        User updatedUser = userService.updateUser(userId, request);
        return ResponseEntity.ok(userMapper.userToDto(updatedUser));
    }
}
```

### 방어 전략 4: 별도의 관리자 API로 민감한 필드 분리

```java
// 사용자용 API: 자신의 프로필만 변경
@RestController
@RequestMapping("/api/users")
public class UserController {
    
    @PutMapping("/{userId}")
    public ResponseEntity<UserDto> updateUserProfile(
            @PathVariable Long userId,
            @RequestBody UserProfileUpdateRequest request,  // 안전한 필드만
            @AuthenticationPrincipal CustomUserDetails userDetails) {
        
        // username, email, phone만 변경 가능
        User updatedUser = userService.updateUserProfile(userId, request);
        return ResponseEntity.ok(new UserDto(updatedUser));
    }
}

// 관리자용 API: 역할과 상태 변경
@RestController
@RequestMapping("/api/admin/users")
public class AdminUserController {
    
    @Autowired
    private UserService userService;
    
    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/{userId}/role")
    public ResponseEntity<UserDto> changeUserRole(
            @PathVariable Long userId,
            @RequestBody UserRoleChangeRequest request) {  // 역할만
        
        // 역할 변경은 별도 API에서만 가능
        User updatedUser = userService.changeUserRole(userId, request);
        return ResponseEntity.ok(new UserDto(updatedUser));
    }
    
    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/{userId}/account-balance")
    public ResponseEntity<UserDto> adjustAccountBalance(
            @PathVariable Long userId,
            @RequestBody AccountBalanceAdjustRequest request) {
        
        // 계정 잔액도 별도 API에서만
        User updatedUser = userService.adjustAccountBalance(userId, request);
        return ResponseEntity.ok(new UserDto(updatedUser));
    }
}

// Request DTO들: 각각 필요한 필드만 포함
@Data
public class UserProfileUpdateRequest {
    private String username;
    private String email;
    private String phone;
    // role, accountBalance 없음
}

@Data
public class UserRoleChangeRequest {
    private String role;  // ROLE_USER, ROLE_ADMIN, etc.
}

@Data
public class AccountBalanceAdjustRequest {
    private BigDecimal amount;
    private String reason;  // 로깅용
}
```

### 방어 전략 5: 데이터베이스 계층의 접근 제어

```java
// Spring Security Method-level 보안
@Service
public class UserService {
    
    @Autowired
    private UserRepository userRepository;
    
    // 사용자는 자신의 정보만 조회
    @PreAuthorize("#userId == authentication.principal.userId")
    public User getUserProfile(Long userId) {
        return userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException("User not found"));
    }
    
    // 사용자는 자신의 프로필만 수정
    @PreAuthorize("#userId == authentication.principal.userId")
    public User updateUserProfile(Long userId, UserProfileUpdateRequest request) {
        User user = userRepository.findById(userId).orElseThrow();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPhone(request.getPhone());
        return userRepository.save(user);
    }
    
    // 역할 변경은 ADMIN만
    @PreAuthorize("hasRole('ADMIN')")
    public User changeUserRole(Long userId, UserRoleChangeRequest request) {
        User user = userRepository.findById(userId).orElseThrow();
        user.setRole(Role.valueOf("ROLE_" + request.getRole().toUpperCase()));
        return userRepository.save(user);
    }
    
    // 계정 잔액은 SUPER_ADMIN만
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public User adjustAccountBalance(Long userId, AccountBalanceAdjustRequest request) {
        User user = userRepository.findById(userId).orElseThrow();
        user.setAccountBalance(user.getAccountBalance().add(request.getAmount()));
        return userRepository.save(user);
    }
}
```

---

## 🔬 공격 원리 분석 (공격자 관점의 내부 동작)

### 공격 시나리오 1: 사용자 역할 승격

```
Step 1: 정상 프로필 업데이트 분석
┌─────────────────────────────────────────┐
│ PUT /api/users/100                      │
│ {                                       │
│   "username": "attacker",               │
│   "email": "attacker@example.com",      │
│   "phone": "010-1234-5678"              │
│ }                                       │
│ → 성공 (200 OK)                         │
└─────────────────────────────────────────┘

Step 2: 추가 필드 주입 시도
┌─────────────────────────────────────────┐
│ 공격자의 생각:                           │
│ "API가 모든 필드를 수락하면?            │
│  role, isAdmin 필드도 추가해보자"       │
└─────────────────────────────────────────┘

Step 3: Mass Assignment 공격
┌─────────────────────────────────────────┐
│ PUT /api/users/100                      │
│ {                                       │
│   "username": "attacker",               │
│   "email": "attacker@example.com",      │
│   "phone": "010-1234-5678",             │
│   "role": "ADMIN",        ← 추가!       │
│   "isAdmin": true         ← 추가!       │
│ }                                       │
│ → 200 OK (필드가 모두 적용됨!)          │
└─────────────────────────────────────────┘

Step 4: 권한 확인
┌─────────────────────────────────────────┐
│ GET /api/users/100                      │
│ → {"role": "ADMIN", "isAdmin": true}    │
│   ← 역할 상승 완료!                     │
└─────────────────────────────────────────┘
```

### 공격 시나리오 2: 상품 재정보 조작

```
Step 1: 상품 정보 조회
┌─────────────────────────────────────────┐
│ GET /api/products/123                   │
│ → {                                     │
│     "name": "Product",                  │
│     "price": 50000,                     │
│     "cost": 10000,        ← 비용정보 노출!
│     "stock": 100                        │
│   }                                     │
└─────────────────────────────────────────┘

Step 2: 마진율 계산
┌─────────────────────────────────────────┐
│ 공격자의 분석:                           │
│ Margin = (price - cost) / price         │
│        = (50000 - 10000) / 50000 = 80% │
└─────────────────────────────────────────┘

Step 3: 재정보 수정
┌─────────────────────────────────────────┐
│ PUT /api/products/123                   │
│ {                                       │
│   "price": 50000,                       │
│   "cost": 1000,          ← 변조!        │
│   "stock": 999999        ← 변조!        │
│ }                                       │
│ → 200 OK                                │
└─────────────────────────────────────────┘

Step 4: 악용
┌─────────────────────────────────────────┐
│ 새 마진율: (50000 - 1000) / 50000 = 98% │
│ → 회사 비용 정보 왜곡                   │
│ → 무제한 재고로 대량 구매 시도           │
└─────────────────────────────────────────┘
```

---

## 💻 실전 실험 (취약점 재현 → 공격 → 방어 검증)

### 실험 환경 설정

```java
// 테스트 엔티티 및 DTO
@Entity
@Table(name = "test_users")
public class TestUser {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String username;
    private String email;
    
    @Enumerated(EnumType.STRING)
    private Role role;
    
    private BigDecimal balance;
    
    // getter/setter...
}

public class UserUpdateDto {
    private String username;
    private String email;
    private String role;  // ← 위험한 필드
    private BigDecimal balance;  // ← 위험한 필드
    
    // getter/setter...
}
```

### 취약한 버전 테스트

```java
@SpringBootTest
@AutoConfigureMockMvc
public class MassAssignmentVulnerableTest {
    
    @Autowired
    private MockMvc mockMvc;
    
    @Autowired
    private TestUserRepository testUserRepository;
    
    @Test
    public void testMassAssignment_Vulnerable_RoleEscalation() throws Exception {
        // 사용자 생성 (ROLE_USER)
        TestUser user = new TestUser();
        user.setId(1L);
        user.setUsername("user1");
        user.setEmail("user1@example.com");
        user.setRole(Role.ROLE_USER);
        user.setBalance(new BigDecimal("1000"));
        testUserRepository.save(user);
        
        // 공격: role 필드를 포함한 요청
        String attackPayload = """
            {
              "username": "user1",
              "email": "user1@example.com",
              "role": "ROLE_ADMIN",
              "balance": "999999"
            }
            """;
        
        mockMvc.perform(put("/api/test-users/1")
                .contentType(MediaType.APPLICATION_JSON)
                .content(attackPayload))
            .andExpect(status().isOk());
        
        // 검증: 역할이 변경됨 (취약!)
        TestUser updated = testUserRepository.findById(1L).orElseThrow();
        assertEquals(Role.ROLE_ADMIN, updated.getRole());
        assertEquals(new BigDecimal("999999"), updated.getBalance());
    }
}
```

### 방어된 버전 테스트

```java
@SpringBootTest
@AutoConfigureMockMvc
public class MassAssignmentDefendedTest {
    
    @Autowired
    private MockMvc mockMvc;
    
    @Autowired
    private TestUserRepository testUserRepository;
    
    @Autowired
    private ObjectMapper objectMapper;
    
    @Test
    public void testMassAssignment_Defended_WithDTO() throws Exception {
        // 사용자 생성 (ROLE_USER)
        TestUser user = new TestUser();
        user.setId(1L);
        user.setUsername("user1");
        user.setEmail("user1@example.com");
        user.setRole(Role.ROLE_USER);
        user.setBalance(new BigDecimal("1000"));
        testUserRepository.save(user);
        
        // 안전한 DTO만 필드 포함
        @Data
        class SafeUserUpdateRequest {
            private String username;
            private String email;
            // role과 balance 필드는 없음!
        }
        
        SafeUserUpdateRequest request = new SafeUserUpdateRequest();
        request.setUsername("updated");
        request.setEmail("updated@example.com");
        
        // 공격자가 추가로 role과 balance를 보낸다면?
        String attackPayload = objectMapper.writeValueAsString(request);
        // DTO에 없는 필드는 무시됨
        
        mockMvc.perform(put("/api/test-users/1")
                .contentType(MediaType.APPLICATION_JSON)
                .content(attackPayload))
            .andExpect(status().isOk());
        
        // 검증: 역할은 변경되지 않음 (방어됨!)
        TestUser updated = testUserRepository.findById(1L).orElseThrow();
        assertEquals(Role.ROLE_USER, updated.getRole());
        assertEquals(new BigDecimal("1000"), updated.getBalance());
        assertEquals("updated", updated.getUsername());
    }
    
    @Test
    public void testMassAssignment_Defended_WithJsonProperty() throws Exception {
        // @JsonProperty(access = READ_ONLY) 어노테이션 테스트
        
        @Entity
        class ProtectedUser {
            @Id
            private Long id;
            private String username;
            
            @JsonProperty(access = JsonProperty.Access.READ_ONLY)
            private Role role;
        }
        
        String json = """
            {
              "id": 1,
              "username": "user1",
              "role": "ROLE_ADMIN"
            }
            """;
        
        ProtectedUser user = objectMapper.readValue(json, ProtectedUser.class);
        
        // role은 READ_ONLY이므로 무시됨
        assertNotEquals(Role.ROLE_ADMIN, user.getRole());
    }
}
```

### Jackson 설정을 이용한 전역 방어

```java
@Configuration
public class JacksonConfig {
    
    @Bean
    public ObjectMapper objectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        
        // 알려지지 않은 필드는 모두 무시
        mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        
        // 빈 생성자 필수 (역직렬화시)
        mapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);
        
        return mapper;
    }
}

// 또는 엔티티/DTO에 적용
@JsonIgnoreProperties(ignoreUnknown = true)
public class UserUpdateRequest {
    private String username;
    private String email;
}
```

---

## 📊 공격 성공 조건 vs 방어 성공 조건 비교

| 항목 | 공격 성공 조건 | 방어 성공 조건 |
|------|--------------|--------------|
| **API가 수락하는 필드** | 모든 JSON 필드 | DTO에 정의된 필드만 |
| **Entity와 DTO** | 동일 또는 직접 사용 | 명확히 분리 |
| **Jackson 어노테이션** | 없거나 최소한 | @JsonIgnore, @JsonProperty(READ_ONLY) |
| **MapStruct 사용** | 불필요 | 명시적 매핑만 |
| **요청 예시** | 모든 필드 변경 가능 | 허용된 필드만 변경 |
| **응답 데이터** | 민감 정보 노출 | 공개 필드만 반환 |

---

## ⚖️ 트레이드오프 (보안 강화 vs 사용성/성능)

### 트레이드오프 1: DTO 개수 증가 vs 보안

**문제**: 각 엔드포인트마다 Request/Response DTO를 만들어야 함
```
User 엔티티 관련:
- UserCreateRequest DTO
- UserUpdateRequest DTO
- UserProfileUpdateRequest DTO
- UserRoleChangeRequest DTO
- UserDto (응답)
- AdminUserDto (응답)
...

→ 많은 보일러플레이트 코드 발생
```

**해결책**: 제네릭 DTO + 검증 로직
```java
@Data
@GenericObject
public class ApiRequest<T> {
    @Valid
    private T data;
    
    private List<String> allowedFields;  // 명시적으로 허용된 필드 목록
}

// 또는 동적 필드 검증
@Component
public class FieldValidator {
    public void validateAllowedFields(Object object, List<String> allowed) {
        // 런타임에 필드 검증
    }
}
```

### 트레이드오프 2: 성능 vs 보안

**문제**: MapStruct 추가, 필드 검증 등으로 인한 오버헤드
```
- 매번 DTO → Entity 변환
- 필드 검증
- @JsonProperty 확인
```

**해결책**: 캐싱 + 컴파일 타임 생성
```java
@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface UserMapper {
    // MapStruct는 컴파일 타임에 클래스 생성하므로 런타임 비용 거의 없음
}
```

### 트레이드오프 3: 유연성 vs 보안

**문제**: 새로운 필드 추가 시 DTO도 수정해야 함
```
요구사항: 사용자 계약 관련 필드 추가 필요
→ UserUpdateRequest DTO 수정 필요
→ 컨트롤러, 서비스 수정 필요
```

**해결책**: 필드 기반 권한 검증
```java
@Component
public class DynamicFieldAuthorizer {
    
    private Map<String, Set<Role>> fieldPermissions = Map.of(
        "username", Set.of(Role.ROLE_USER),
        "email", Set.of(Role.ROLE_USER),
        "role", Set.of(Role.ROLE_ADMIN),
        "balance", Set.of(Role.ROLE_SUPER_ADMIN)
    );
    
    public boolean canModifyField(String fieldName, Role userRole) {
        return fieldPermissions.getOrDefault(fieldName, Set.of())
            .contains(userRole);
    }
}
```

---

## 📌 핵심 정리

1. **Mass Assignment의 본질**: API가 모든 JSON 필드를 엔티티에 매핑하는 것
2. **위험성**: 의도하지 않은 필드(role, balance 등)까지 변경 가능
3. **방어 원칙**:
   - Request/Response DTO를 Entity와 분리
   - DTO에는 변경 가능한 필드만 포함
   - @JsonIgnore 또는 @JsonProperty(READ_ONLY) 사용
   - MapStruct로 명시적 필드 매핑
   - 민감한 필드는 별도 관리자 API 분리

4. **Spring 활용**:
   - Jackson 어노테이션: @JsonIgnore, @JsonProperty, @JsonIgnoreProperties
   - MapStruct: 컴파일 타임 필드 매핑
   - 메서드 보안: 필드별 권한 검증

5. **테스트**: 항상 의도하지 않은 필드가 변경되지 않는지 검증

---

## 🤔 생각해볼 문제 (+ 해설)

### 문제 1: API 응답에도 민감한 필드를 포함할 수 있나?

**상황**: 비용 정보(cost), 마진율(margin) 등이 응답에 포함될 수 있나?

**해설**:
응답 DTO를 별도로 만들어 공개할 필드만 포함해야 합니다:

```java
// Entity: 모든 정보 포함
@Entity
public class Product {
    private String name;
    private BigDecimal price;
    private BigDecimal cost;  // ← 내부용
    private int stock;
}

// 공개 응답 DTO: 공개할 필드만
@Data
public class ProductPublicDto {
    private String name;
    private BigDecimal price;
    // cost, stock은 포함하지 않음!
}

// 관리자 응답 DTO: 모든 정보 포함
@Data
public class ProductAdminDto {
    private String name;
    private BigDecimal price;
    private BigDecimal cost;
    private int stock;
}

// 컨트롤러
@GetMapping("/{id}")
public ProductPublicDto getProduct(@PathVariable Long id) {
    return mapper.toPublicDto(productRepository.findById(id).orElseThrow());
}

@GetMapping("/{id}")
@PreAuthorize("hasRole('ADMIN')")
public ProductAdminDto getProductAdmin(@PathVariable Long id) {
    return mapper.toAdminDto(productRepository.findById(id).orElseThrow());
}
```

---

### 문제 2: 중첩된 객체의 필드도 보호해야 하나?

**상황**: User가 Address 객체를 포함할 때, Address의 비공개 필드도?

**해설**:
중첩된 객체도 동일하게 보호해야 합니다:

```java
@Data
class UserUpdateRequest {
    private String username;
    private AddressUpdateRequest address;
}

// AddressUpdateRequest는 공개할 필드만
@Data
class AddressUpdateRequest {
    private String street;
    private String city;
    private String zipCode;
    // country, region 등 민감 정보는 없음
}

// Entity의 Address는 더 많은 정보를 가질 수 있음
@Embeddable
class Address {
    private String street;
    private String city;
    private String zipCode;
    private String country;  // ← DTO에는 없음
    private String latitude;
    private String longitude;  // ← 위치 추적용
}
```

---

### 문제 3: 배치 API에서 대량 업데이트 시 Mass Assignment는?

**상황**: `/api/users/batch-update`에서 여러 사용자를 동시에 업데이트

**해설**:
배치 API도 동일한 필드 검증이 필요합니다:

```java
@Data
class BatchUserUpdateRequest {
    private List<UserUpdateRequest> updates;  // 같은 안전한 DTO 사용
}

@PostMapping("/batch-update")
public List<UserDto> batchUpdate(@RequestBody BatchUserUpdateRequest request) {
    return request.getUpdates().stream()
        .map(update -> userService.updateUser(update))
        .map(UserDto::new)
        .toList();
}
```

<div align="center">

**[⬅️ 이전: 수평적 vs 수직적 권한 상승](./02-horizontal-vertical-privilege-escalation.md)** | **[홈으로 🏠](../README.md)** | **[다음: API Rate Limiting 설계 ➡️](./04-api-rate-limiting.md)**

</div>
