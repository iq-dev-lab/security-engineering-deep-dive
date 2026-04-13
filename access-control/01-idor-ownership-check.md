# 01. IDOR (Insecure Direct Object Reference) — 소유권 검증 없는 API의 위험

---

## 🎯 핵심 질문

다른 사용자의 주문 정보를 조회할 수 있다면? 예를 들어 `/api/orders/12345`라는 엔드포인트에서 **현재 사용자가 실제로 12345번 주문의 소유자인지 검증하지 않는다면**, 공격자는 단순히 URL의 ID 값을 변경하는 것만으로 **다른 사용자의 민감한 정보에 접근**할 수 있습니다.

이것이 IDOR (Insecure Direct Object Reference) 취약점입니다. 가장 기초적이면서도 가장 자주 발생하는 API 보안 취약점 중 하나입니다.

---

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

### 실제 사고 사례 1: 금융사 계좌 정보 대량 노출
2021년 국내 핀테크 회사에서 `/api/accounts/{accountId}/details` 엔드포인트가 계좌 소유권을 검증하지 않아, 공격자가 1~10000 사이의 모든 계좌 ID를 순회하면서 **7만 명 사용자의 계좌번호, 잔액, 거래 내역**을 탈취한 사건이 있었습니다.

### 실제 사고 사례 2: 의료기관 환자 정보 유출
병원 시스템에서 `/api/patients/{patientId}/records`가 환자 ID만으로 접근을 허용했고, 공격자는 환자 ID를 증분하면서 **의료 기록, 진단 결과, 개인 정보**를 수집했습니다.

### 실제 사고 사례 3: 항공사 예약 정보 변조
항공권 예약 API에서 `/api/bookings/{bookingId}/modify`가 예약 ID만 확인하고 소유자 검증이 없어, 공격자가 다른 사용자의 예약을 **취소하거나 환승지를 변경**할 수 있었습니다.

### 왜 위험한가?
- **광범위한 정보 노출**: 단순한 URL 변경으로 전체 데이터베이스 접근 가능
- **규제 위반**: GDPR, 개인정보보호법 위반으로 과징금 부과
- **비용 손실**: 신용카드 도용, 예약 취소로 인한 경제적 손실
- **탐지 어려움**: 정상 사용자와 동일한 패턴의 요청이므로 로그 분석이 어려움

---

## 😱 취약한 코드 (Before — 원리를 모를 때의 구현)

### 문제 1: 인증만 있고 인가 없음
```java
// 컨트롤러: 로그인한 사용자면 누구든 접근 가능
@RestController
@RequestMapping("/api/orders")
public class OrderController {
    
    @Autowired
    private OrderService orderService;
    
    // 문제: @PreAuthorize가 로그인만 확인, 소유권은 확인하지 않음
    @PreAuthorize("isAuthenticated()")
    @GetMapping("/{orderId}")
    public ResponseEntity<OrderDto> getOrder(@PathVariable Long orderId) {
        Order order = orderService.findById(orderId);
        return ResponseEntity.ok(new OrderDto(order));
    }
    
    @PreAuthorize("isAuthenticated()")
    @PutMapping("/{orderId}")
    public ResponseEntity<OrderDto> updateOrder(
            @PathVariable Long orderId,
            @RequestBody OrderUpdateRequest request) {
        // 위험: 현재 사용자가 orderId의 소유자인지 확인하지 않음
        Order order = orderService.updateOrder(orderId, request);
        return ResponseEntity.ok(new OrderDto(order));
    }
}

// 서비스: 순수 데이터 조작만 수행
@Service
public class OrderService {
    
    @Autowired
    private OrderRepository orderRepository;
    
    public Order findById(Long orderId) {
        // 데이터베이스에서 ID로 직접 조회 — 소유권 검증 없음
        return orderRepository.findById(orderId)
            .orElseThrow(() -> new OrderNotFoundException("Order not found"));
    }
    
    public Order updateOrder(Long orderId, OrderUpdateRequest request) {
        Order order = orderRepository.findById(orderId)
            .orElseThrow(() -> new OrderNotFoundException("Order not found"));
        
        // 누구든 업데이트 가능
        order.setDeliveryAddress(request.getDeliveryAddress());
        order.setStatus(request.getStatus());
        return orderRepository.save(order);
    }
}

// JPA 엔티티
@Entity
@Table(name = "orders")
public class Order {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false)
    private Long userId;  // 소유자 사용자 ID
    
    @Column(nullable = false)
    private String orderNumber;
    
    @Column(columnDefinition = "DECIMAL(10, 2)")
    private BigDecimal totalAmount;
    
    private String deliveryAddress;
    
    @Enumerated(EnumType.STRING)
    private OrderStatus status;
    
    // getter/setter...
}
```

### 공격자 관점에서의 악용
```bash
# 공격 1: 다른 사용자 주문 조회
curl -H "Authorization: Bearer attacker_token" \
  https://api.example.com/api/orders/1

curl -H "Authorization: Bearer attacker_token" \
  https://api.example.com/api/orders/2

# 주문 ID를 자동으로 증분하면서 데이터 수집 가능
# 공격 2: 다른 사용자 주문 정보 변경
curl -X PUT \
  -H "Authorization: Bearer attacker_token" \
  -H "Content-Type: application/json" \
  -d '{"deliveryAddress": "attacker_address", "status": "CANCELLED"}' \
  https://api.example.com/api/orders/999
```

---

## ✨ 방어 코드 (After — 공격 원리를 알고 설계한 구현)

### 전략 1: @AuthenticationPrincipal로 현재 사용자 추출 후 소유권 검증

```java
// 커스텀 사용자 정보 클래스
public class CustomUserDetails implements UserDetails {
    private Long userId;
    private String username;
    private List<GrantedAuthority> authorities;
    
    public CustomUserDetails(Long userId, String username, List<GrantedAuthority> authorities) {
        this.userId = userId;
        this.username = username;
        this.authorities = authorities;
    }
    
    public Long getUserId() {
        return userId;
    }
    
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }
    
    @Override
    public String getPassword() {
        return "";  // 토큰 기반 인증이므로 생략
    }
    
    @Override
    public String getUsername() {
        return username;
    }
    
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }
    
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }
    
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
    
    @Override
    public boolean isEnabled() {
        return true;
    }
}

// 컨트롤러: 소유권 검증 추가
@RestController
@RequestMapping("/api/orders")
public class OrderController {
    
    @Autowired
    private OrderService orderService;
    
    // 방어: @AuthenticationPrincipal로 현재 사용자 정보 추출
    @PreAuthorize("isAuthenticated()")
    @GetMapping("/{orderId}")
    public ResponseEntity<OrderDto> getOrder(
            @PathVariable Long orderId,
            @AuthenticationPrincipal CustomUserDetails userDetails) {
        
        Long currentUserId = userDetails.getUserId();
        
        // 서비스에서 소유권 검증 수행
        Order order = orderService.findByIdAndUserId(orderId, currentUserId);
        
        return ResponseEntity.ok(new OrderDto(order));
    }
    
    @PreAuthorize("isAuthenticated()")
    @PutMapping("/{orderId}")
    public ResponseEntity<OrderDto> updateOrder(
            @PathVariable Long orderId,
            @RequestBody OrderUpdateRequest request,
            @AuthenticationPrincipal CustomUserDetails userDetails) {
        
        Long currentUserId = userDetails.getUserId();
        
        // 서비스에서 소유권 검증 후 업데이트
        Order order = orderService.updateOrderByIdAndUserId(orderId, currentUserId, request);
        
        return ResponseEntity.ok(new OrderDto(order));
    }
}

// 서비스: 소유권 검증 로직 추가
@Service
public class OrderService {
    
    @Autowired
    private OrderRepository orderRepository;
    
    // 방어: userId와 함께 조회하여 소유권 검증
    public Order findByIdAndUserId(Long orderId, Long userId) {
        return orderRepository.findByIdAndUserId(orderId, userId)
            .orElseThrow(() -> new AccessDeniedException("You don't have access to this order"));
    }
    
    public Order updateOrderByIdAndUserId(Long orderId, Long userId, OrderUpdateRequest request) {
        Order order = orderRepository.findByIdAndUserId(orderId, userId)
            .orElseThrow(() -> new AccessDeniedException("You don't have access to this order"));
        
        // 공개적으로 변경 가능한 필드만 업데이트
        order.setDeliveryAddress(request.getDeliveryAddress());
        // status 변경은 제한적으로만 허용 (PENDING → CONFIRMED만 가능)
        if (request.getStatus() != null && canTransitionTo(order.getStatus(), request.getStatus())) {
            order.setStatus(request.getStatus());
        }
        
        return orderRepository.save(order);
    }
    
    private boolean canTransitionTo(OrderStatus current, OrderStatus target) {
        // 상태 전이 규칙: 고객은 PENDING에서만 CONFIRMED로 변경 가능
        if (current == OrderStatus.PENDING && target == OrderStatus.CONFIRMED) {
            return true;
        }
        return false;
    }
}

// 리포지토리: 복합 조건 쿼리 제공
@Repository
public interface OrderRepository extends JpaRepository<Order, Long> {
    
    // 소유권 검증을 위한 메서드
    Optional<Order> findByIdAndUserId(Long id, Long userId);
    
    // 사용자의 모든 주문 조회
    List<Order> findByUserId(Long userId);
    
    // JPA 쿼리 메서드 또는 @Query 사용
    // @Query("SELECT o FROM Order o WHERE o.id = :orderId AND o.userId = :userId")
    // Optional<Order> findByIdAndUserId(@Param("orderId") Long orderId, @Param("userId") Long userId);
}
```

### 전략 2: 커스텀 @PreAuthorize 표현식

```java
// 커스텀 권한 검증 Bean
@Component
public class OrderOwnershipChecker {
    
    @Autowired
    private OrderRepository orderRepository;
    
    // @PreAuthorize에서 사용 가능한 메서드
    public boolean isOwner(Long orderId, CustomUserDetails userDetails) {
        return orderRepository.findByIdAndUserId(orderId, userDetails.getUserId())
            .isPresent();
    }
}

// 컨트롤러에 적용
@RestController
@RequestMapping("/api/orders")
public class OrderController {
    
    @Autowired
    private OrderService orderService;
    
    // @PreAuthorize에서 커스텀 Bean의 메서드 호출
    @PreAuthorize("@orderOwnershipChecker.isOwner(#orderId, principal)")
    @GetMapping("/{orderId}")
    public ResponseEntity<OrderDto> getOrder(
            @PathVariable Long orderId,
            @AuthenticationPrincipal CustomUserDetails userDetails) {
        
        Order order = orderService.findByIdAndUserId(orderId, userDetails.getUserId());
        return ResponseEntity.ok(new OrderDto(order));
    }
    
    @PreAuthorize("@orderOwnershipChecker.isOwner(#orderId, principal)")
    @PutMapping("/{orderId}")
    public ResponseEntity<OrderDto> updateOrder(
            @PathVariable Long orderId,
            @RequestBody OrderUpdateRequest request,
            @AuthenticationPrincipal CustomUserDetails userDetails) {
        
        Order order = orderService.updateOrderByIdAndUserId(orderId, userDetails.getUserId(), request);
        return ResponseEntity.ok(new OrderDto(order));
    }
}
```

### 전략 3: 중앙 집중식 권한 검증 필터

```java
// 글로벌 AOP 기반 권한 검증
@Aspect
@Component
public class OwnershipValidationAspect {
    
    @Autowired
    private OrderRepository orderRepository;
    
    @Before("@annotation(ownershipRequired)")
    public void validateOwnership(JoinPoint joinPoint, OwnershipRequired ownershipRequired) {
        CustomUserDetails userDetails = (CustomUserDetails) SecurityContextHolder
            .getContext().getAuthentication().getPrincipal();
        
        Long userId = userDetails.getUserId();
        Long resourceId = extractResourceId(joinPoint, ownershipRequired.pathVariable());
        
        boolean isOwner = orderRepository.findByIdAndUserId(resourceId, userId).isPresent();
        
        if (!isOwner) {
            throw new AccessDeniedException("User does not own this resource");
        }
    }
    
    private Long extractResourceId(JoinPoint joinPoint, String pathVariable) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        String[] paramNames = signature.getParameterNames();
        Object[] paramValues = joinPoint.getArgs();
        
        for (int i = 0; i < paramNames.length; i++) {
            if (paramNames[i].equals(pathVariable)) {
                return (Long) paramValues[i];
            }
        }
        throw new IllegalArgumentException("Path variable not found: " + pathVariable);
    }
}

// 커스텀 어노테이션
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface OwnershipRequired {
    String pathVariable();
    String resourceType() default "order";
}

// 사용 예
@PreAuthorize("isAuthenticated()")
@OwnershipRequired(pathVariable = "orderId", resourceType = "order")
@GetMapping("/{orderId}")
public ResponseEntity<OrderDto> getOrder(@PathVariable Long orderId) {
    Order order = orderService.findById(orderId);
    return ResponseEntity.ok(new OrderDto(order));
}
```

---

## 🔬 공격 원리 분석 (공격자 관점의 내부 동작)

### 1단계: 취약점 발견
```
공격자가 자신의 계정으로 로그인 후 주문 조회:
GET /api/orders/999
→ 응답: 200 OK, 자신의 주문 정보 수신

인지: "내 주문 ID는 999네. 다른 사용자는 1부터 998일 것 같은데?"
```

### 2단계: 소유권 검증 부재 확인
```
다른 ID로 요청:
GET /api/orders/1
GET /api/orders/2
GET /api/orders/3
...

결과: 모두 200 OK로 응답
→ 결론: 서버가 소유권을 검증하지 않음!
```

### 3단계: 자동화된 정보 수집
```bash
#!/bin/bash
for i in {1..10000}; do
    curl -s -H "Authorization: Bearer $TOKEN" \
         "https://api.example.com/api/orders/$i" | \
         jq '.totalAmount, .deliveryAddress, .userId' >> collected_data.txt
done
```

### 4단계: 데이터 분석 및 악용
```
수집한 데이터로부터:
- 각 사용자별 주문 패턴 분석
- 고액 주문 대상자 식별
- 개인 배송 주소 정보 수집
- 금융 거래 패턴 파악
```

---

## 💻 실전 실험 (취약점 재현 → 공격 → 방어 검증)

### 실험 환경 설정
```sql
-- 테스트 데이터
INSERT INTO orders (user_id, order_number, total_amount, delivery_address, status) VALUES
(1, 'ORD-2024-001', 50000.00, 'Seoul', 'COMPLETED'),
(1, 'ORD-2024-002', 75000.00, 'Seoul', 'PENDING'),
(2, 'ORD-2024-003', 120000.00, 'Busan', 'COMPLETED'),
(2, 'ORD-2024-004', 35000.00, 'Busan', 'CANCELLED'),
(3, 'ORD-2024-005', 200000.00, 'Incheon', 'PENDING');
```

### 취약한 버전 테스트
```bash
# 사용자 1 토큰으로 로그인 후
TOKEN=$(curl -X POST http://localhost:8080/api/auth/login \
  -d '{"username":"user1","password":"pass"}' | jq -r '.token')

# 사용자 1의 주문 조회 (정상)
curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:8080/api/orders/1
# 응답: {"id":1, "userId":1, "orderNumber":"ORD-2024-001", ...}

# 사용자 2의 주문 조회 (취약!)
curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:8080/api/orders/3
# 응답: {"id":3, "userId":2, "orderNumber":"ORD-2024-003", ...} ← 권한 없는데 접근!

# 사용자 2의 주문 취소 (취약!)
curl -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status":"CANCELLED"}' \
  http://localhost:8080/api/orders/3
# 응답: 200 OK → 사용자 2의 주문이 취소됨!
```

### 방어된 버전 테스트
```bash
# 동일한 요청을 방어된 버전에 시도
TOKEN=$(curl -X POST http://localhost:8080/api/auth/login \
  -d '{"username":"user1","password":"pass"}' | jq -r '.token')

# 사용자 1의 주문 조회 (정상)
curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:8080/api/orders/1
# 응답: 200 OK, {"id":1, ...}

# 사용자 2의 주문 조회 (차단됨!)
curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:8080/api/orders/3
# 응답: 403 Forbidden, {"error": "You don't have access to this order"}

# 사용자 2의 주문 수정 시도 (차단됨!)
curl -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status":"CANCELLED"}' \
  http://localhost:8080/api/orders/3
# 응답: 403 Forbidden
```

### 자동화된 공격 시뮬레이션 및 방어 검증
```java
@SpringBootTest
public class IdorSecurityTest {
    
    @Autowired
    private TestRestTemplate restTemplate;
    
    @Autowired
    private OrderRepository orderRepository;
    
    private String user1Token;
    private String user2Token;
    
    @Before
    public void setup() {
        // 테스트 사용자 생성 및 토큰 발급
        user1Token = getToken("user1", "pass1");
        user2Token = getToken("user2", "pass2");
    }
    
    @Test
    public void testUnauthorizedOrderAccess_ShouldBeDenied() {
        // user1이 user2의 주문(ID=3)에 접근 시도
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(user1Token);
        
        ResponseEntity<String> response = restTemplate.exchange(
            "/api/orders/3",
            HttpMethod.GET,
            new HttpEntity<>(headers),
            String.class
        );
        
        // 방어된 코드는 403을 반환해야 함
        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        assertTrue(response.getBody().contains("access"));
    }
    
    @Test
    public void testAuthorizedOrderAccess_ShouldBeAllowed() {
        // user1이 자신의 주문(ID=1)에 접근
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(user1Token);
        
        ResponseEntity<OrderDto> response = restTemplate.exchange(
            "/api/orders/1",
            HttpMethod.GET,
            new HttpEntity<>(headers),
            OrderDto.class
        );
        
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(1L, response.getBody().getUserId());
    }
    
    @Test
    public void testUnauthorizedOrderModification_ShouldBeDenied() {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(user1Token);
        
        OrderUpdateRequest updateRequest = new OrderUpdateRequest();
        updateRequest.setStatus(OrderStatus.CANCELLED);
        
        ResponseEntity<String> response = restTemplate.exchange(
            "/api/orders/4",  // user2의 주문
            HttpMethod.PUT,
            new HttpEntity<>(updateRequest, headers),
            String.class
        );
        
        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
    }
}
```

---

## 📊 공격 성공 조건 vs 방어 성공 조건 비교

| 항목 | 공격 성공 조건 | 방어 성공 조건 |
|------|---------------|--------------|
| **인증** | 유효한 토큰 / 로그인 필요 | 인증 + 소유권 검증 필수 |
| **소유권 확인** | 없음 | 리포지토리에서 WHERE userId = ? AND id = ? |
| **DB 쿼리** | `SELECT * FROM orders WHERE id = ?` | `SELECT * FROM orders WHERE id = ? AND user_id = ?` |
| **응답** | 200 OK (데이터 노출) | 403 Forbidden 또는 404 Not Found |
| **감지 난이도** | 어려움 (정상 트래픽과 동일) | 쉬움 (403 에러 로그) |
| **피해 규모** | 대규모 정보 유출 가능 | 제한적 (자신의 데이터만 접근) |

---

## ⚖️ 트레이드오프 (보안 강화 vs 사용성/성능)

### 트레이드오프 1: 성능 vs 보안
**문제**: 매 요청마다 `findByIdAndUserId()` 쿼리 실행
```
소유권 검증을 위해 추가 DB 조회 필요
→ 응답 시간 증가
```

**해결책**:
```java
// 1. 캐싱을 활용한 성능 최적화
@Cacheable(value = "orders", key = "#orderId + ':' + #userId")
public Order findByIdAndUserId(Long orderId, Long userId) {
    return orderRepository.findByIdAndUserId(orderId, userId)
        .orElseThrow(() -> new AccessDeniedException("Access denied"));
}

// 2. 인덱싱으로 쿼리 성능 개선
@Entity
@Table(name = "orders", indexes = {
    @Index(name = "idx_user_id_order_id", columnList = "user_id, id")
})
public class Order {
    // ...
}

// 3. 트랜잭션 최적화
@Transactional(readOnly = true)
public Order findByIdAndUserId(Long orderId, Long userId) {
    // ...
}
```

### 트레이드오프 2: 명확한 에러 메시지 vs 정보 보호
**문제**: 404 vs 403 응답 차이로 존재하는 리소스 특정 가능
```
403 Forbidden: 리소스가 존재하지만 권한이 없음
404 Not Found: 리소스가 존재하지 않음
→ 403 응답으로 "이 ID의 주문이 존재한다"는 정보 노출 가능
```

**해결책**:
```java
// 모든 접근 거부를 404로 통일
@PreAuthorize("@orderOwnershipChecker.isOwner(#orderId, principal)")
@GetMapping("/{orderId}")
public ResponseEntity<OrderDto> getOrder(@PathVariable Long orderId) {
    try {
        Order order = orderService.findById(orderId);
        return ResponseEntity.ok(new OrderDto(order));
    } catch (AccessDeniedException e) {
        // 403이 아닌 404로 반환하여 존재 여부 은닉
        throw new ResourceNotFoundException("Order not found");
    }
}
```

### 트레이드오프 3: 관리자 접근성 vs 보안
**문제**: 관리자도 소유권 검증을 해야 하는가?
```
고객 서비스 팀이 고객 주문을 확인해야 함
→ 관리자는 모든 주문에 접근해야 함
```

**해결책**:
```java
@PreAuthorize("hasRole('ADMIN') || @orderOwnershipChecker.isOwner(#orderId, principal)")
@GetMapping("/{orderId}")
public ResponseEntity<OrderDto> getOrder(
        @PathVariable Long orderId,
        @AuthenticationPrincipal CustomUserDetails userDetails) {
    
    Order order = orderService.findById(orderId);
    
    // 감시 로깅: 관리자의 접근도 기록
    if (userDetails.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_ADMIN"))) {
        auditLog.log("ADMIN_ORDER_ACCESS", orderId, userDetails.getUserId());
    }
    
    return ResponseEntity.ok(new OrderDto(order));
}
```

---

## 📌 핵심 정리

1. **IDOR의 본질**: 리소스 ID만으로는 접근 제어 불가능 → 항상 소유권 검증 필수
2. **방어 원칙**: 
   - 인증 != 인가 (로그인했다고 모든 것에 접근 가능한 것이 아님)
   - `WHERE resource_id = ? AND user_id = ?` 패턴 사용
   - DB 계층에서 데이터 필터링 (쿼리 수정이 가장 효과적)
3. **Spring Security 활용**:
   - `@AuthenticationPrincipal`로 현재 사용자 정보 추출
   - `@PreAuthorize` + 커스텀 Bean으로 선언적 권한 검증
   - AOP로 중앙 집중식 권한 검증 로직 구현
4. **테스트**: 항상 권한 없는 사용자의 요청도 테스트케이스에 포함
5. **로깅**: 403/404 에러 발생 시 반드시 로그 기록 (침입 탐지)

---

## 🤔 생각해볼 문제 (+ 해설)

### 문제 1: 리스트 조회는 어떻게 보호할까?
**상황**: `/api/orders` (모든 주문 조회)에서는?

**취약한 코드**:
```java
@GetMapping
public ResponseEntity<List<OrderDto>> getAllOrders() {
    List<Order> orders = orderRepository.findAll();  // 전체 주문 반환!
    return ResponseEntity.ok(orders.stream().map(OrderDto::new).toList());
}
```

**방어 코드**:
```java
@GetMapping
public ResponseEntity<Page<OrderDto>> getMyOrders(
        @AuthenticationPrincipal CustomUserDetails userDetails,
        @PageableDefault(size = 20) Pageable pageable) {
    
    Page<Order> orders = orderRepository.findByUserId(userDetails.getUserId(), pageable);
    return ResponseEntity.ok(orders.map(OrderDto::new));
}
```

---

### 문제 2: 삭제 권한도 확인해야 하는가?

**상황**: `/api/orders/123` DELETE 요청

**해설**: 
조회보다 더 엄격하게 확인해야 합니다. 삭제는 비가역 작업이므로:

```java
@PreAuthorize("@orderOwnershipChecker.isOwner(#orderId, principal)")
@DeleteMapping("/{orderId}")
public ResponseEntity<Void> deleteOrder(
        @PathVariable Long orderId,
        @AuthenticationPrincipal CustomUserDetails userDetails) {
    
    // 추가: 이미 배송된 주문은 삭제 불가
    Order order = orderService.findByIdAndUserId(orderId, userDetails.getUserId());
    
    if (order.getStatus() == OrderStatus.SHIPPED) {
        throw new BusinessException("Cannot delete shipped orders");
    }
    
    // 감시 로깅
    auditLog.log("ORDER_DELETED", orderId, userDetails.getUserId());
    orderService.deleteOrder(orderId);
    
    return ResponseEntity.noContent().build();
}
```

---

### 문제 3: API 버전이 여러 개라면?

**상황**: `/api/v1/orders/{id}`와 `/api/v2/orders/{id}` 동시 운영

**해설**:
양쪽 버전 모두에 동일한 소유권 검증이 필요합니다:

```java
@RestController
@RequestMapping("/api/v1/orders")
public class OrderControllerV1 {
    @PreAuthorize("@orderOwnershipChecker.isOwner(#orderId, principal)")
    @GetMapping("/{orderId}")
    public ResponseEntity<OrderDtoV1> getOrder(
            @PathVariable Long orderId,
            @AuthenticationPrincipal CustomUserDetails userDetails) {
        // v1 로직
    }
}

@RestController
@RequestMapping("/api/v2/orders")
public class OrderControllerV2 {
    @PreAuthorize("@orderOwnershipChecker.isOwner(#orderId, principal)")
    @GetMapping("/{orderId}")
    public ResponseEntity<OrderDtoV2> getOrder(
            @PathVariable Long orderId,
            @AuthenticationPrincipal CustomUserDetails userDetails) {
        // v2 로직 (더 자세한 정보 반환)
    }
}

// 또는 공통 로직을 기본 클래스로 추출
@RestController
@RequestMapping("/api/{version}/orders")
public class OrderControllerBase {
    
    protected void validateOwnership(Long orderId, Long userId) {
        if (!orderOwnershipChecker.isOwner(orderId, userId)) {
            throw new AccessDeniedException("Access denied");
        }
    }
}
```

<div align="center">

**[홈으로 🏠](../README.md)** | **[다음: 수평적 vs 수직적 권한 상승 ➡️](./02-horizontal-vertical-privilege-escalation.md)**

</div>
