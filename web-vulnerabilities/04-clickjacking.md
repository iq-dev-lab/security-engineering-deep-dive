# Clickjacking 공격과 방어 완전 가이드

---

## 🎯 핵심 질문

- 투명 iframe이 사용자의 의도하지 않은 클릭을 유도하는 원리는?
- `X-Frame-Options: DENY`와 `frame-ancestors 'none'`의 차이는?
- Clickjacking으로 은행 송금, 계정 삭제 같은 상태 변경이 가능한가?
- 페이스북의 "좋아요" 버튼 하이재킹 사건이 무엇인가?

---

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

### Facebook의 "좋아요" 버튼 Clickjacking (2008)
페이스북의 "좋아요" 버튼이 투명 iframe 아래 숨겨져 있었습니다. 사용자가 "Click here to win an iPhone!" 같은 버튼을 클릭하면, 실제로는 페이스북 페이지의 "좋아요" 버튼을 클릭하게 되어 원하지 않은 페이지를 추천하게 되었습니다. 수백만 사용자가 자신도 모르게 악성 페이지를 추천했습니다.

### 유튜브 동영상 구독 Clickjacking (2010)
유튜브 동영상이 투명 iframe으로 임베드되어, 사용자가 의도하지 않은 채널을 구독하게 되었습니다. 특정 채널이 정상 기능처럼 보이는 클릭 가능한 영역 아래 숨겨져 있었습니다.

### Adobe Flash 권한 Clickjacking (2013)
플래시 플레이어의 카메라/마이크 권한 승인 버튼이 Clickjacking 대상이 되어, 사용자가 모르는 사이에 카메라 접근을 허락했습니다. 이는 해커가 사용자의 노트북 카메라를 활성화하고 감시할 수 있게 했습니다.

---

## 😱 취약한 코드 (Before — 원리를 모를 때의 구현)

### 1. X-Frame-Options 헤더 없음

**취약한 Spring Configuration**
```java
@Configuration
public class WebConfig implements WebMvcConfigurer {
    
    // ❌ 문제: X-Frame-Options 헤더를 설정하지 않음
    
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new InterceptorAdapter() {
            @Override
            public boolean preHandle(HttpServletRequest request,
                                    HttpServletResponse response,
                                    Object handler) throws Exception {
                // X-Frame-Options 설정 안 함!
                // 브라우저가 기본값으로 동작: 아무 제약 없음
                return true;
            }
        });
    }
}
```

**결과**
```
- 어떤 도메인이든 해당 페이지를 iframe으로 임베드 가능
- 공격자가 투명 iframe을 겹쳐서 Clickjacking 공격 가능
```

---

### 2. CSP frame-ancestors 설정 없음

**취약한 Spring Security 설정**
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .headers(headers -> headers
                .frameOptions(frameOptions -> frameOptions
                    .sameOrigin() // 같은 출처만 허용
                )
                // ❌ 문제: CSP frame-ancestors 설정 없음
                // Spring Security의 X-Frame-Options만으로는 부족
                // 구형 브라우저는 CSP를 모를 수 있음
            );
        
        return http.build();
    }
}
```

---

### 3. 민감한 기능을 iframe으로 접근 가능하게 한 경우

**취약한 Controller**
```java
@RestController
@RequestMapping("/api")
public class TransferController {
    
    @PostMapping("/transfer")
    public ResponseEntity<?> transfer(@RequestParam Long recipientId,
                                      @RequestParam BigDecimal amount) {
        // ❌ 문제 1: CSRF 토큰 검증이 없음
        // 또는 CSRF 검증이 있지만 iframe 안에서도 자동으로 전송됨
        
        // ❌ 문제 2: CORS 정책이 너무 느슨함
        // preflight 요청이 없어서 다른 도메인에서도 요청 가능
        
        Account account = getCurrentUserAccount();
        account.transfer(recipientId, amount);
        
        return ResponseEntity.ok("송금 완료");
    }
    
    @GetMapping("/confirm-transfer")
    public String confirmTransfer(@RequestParam Long transferId) {
        // ❌ 문제 3: GET 요청으로 상태 변경
        // Clickjacking에 더 취약함
        
        Transfer transfer = transferRepository.findById(transferId).orElse(null);
        transfer.setStatus(TransferStatus.CONFIRMED);
        transferRepository.save(transfer);
        
        return "redirect:/account";
    }
}
```

---

### 4. 클릭 가능한 영역을 올바르게 보호하지 않은 경우

**취약한 HTML**
```html
<!DOCTYPE html>
<html>
<head>
    <style>
        /* ❌ 문제: 버튼 스타일이 일반적으로 보임 */
        .claim-button {
            padding: 20px;
            font-size: 24px;
            background: #4CAF50;
            color: white;
            border: none;
            cursor: pointer;
        }
        
        /* ❌ 투명 iframe이 버튼 위에 겹쳐짐 */
        iframe {
            position: absolute;
            top: 100px;
            left: 50px;
            width: 200px;
            height: 50px;
            opacity: 0;    /* 투명하게 만듦 */
            z-index: 999;  /* 앞에 나타나도록 설정 */
        }
    </style>
</head>
<body>
    <h1>클릭하세요! iPhone을 무료로 받으세요!</h1>
    
    <!-- 사용자가 클릭하려는 버튼 -->
    <button class="claim-button">여기를 클릭하세요</button>
    
    <!-- 실제로는 facebook.com의 "좋아요" 버튼이 버튼 위에 투명하게 겹쳐있음 -->
    <iframe src="https://facebook.com/like-button" 
            style="opacity: 0; position: absolute;"></iframe>
    
    <!-- 또는 Twitter 팔로우 버튼 -->
    <iframe src="https://twitter.com/follow-button" 
            style="opacity: 0; position: absolute;"></iframe>
</body>
</html>
```

**공격 흐름**
```
1. 공격자가 위 HTML을 자신의 사이트에 배포
2. 사용자가 "여기를 클릭하세요" 버튼을 클릭하려 함
3. 실제로는 투명 iframe 아래의 Facebook "좋아요" 버튼을 클릭
4. 사용자가 의도하지 않게 악성 페이지에 "좋아요" 클릭
5. 사용자의 팔로워들이 해당 악성 페이지를 봄
6. Worm 효과로 확산
```

---

### 5. Clickjacking 대응이 있지만 불완전한 경우

**불완전한 방어 1: 버튼 비활성화**
```html
<!DOCTYPE html>
<html>
<body>
    <button id="sensitiveBtn" onclick="deleteAccount()">계정 삭제</button>
    
    <script>
        // ❌ 문제: JavaScript로만 방어 (클라이언트 사이드)
        // iframe 공격자는 이 JavaScript를 무시할 수 있음
        
        // 시도 1: 클릭 가능 여부 검사
        document.getElementById('sensitiveBtn').addEventListener('click', function(e) {
            if (window !== window.top) {
                // iframe 안에 있으면 클릭 무시
                e.preventDefault();
                alert('이 기능은 팝업에서 사용할 수 없습니다');
                return false;
            }
        });
    </script>
</body>
</html>
```

**공격자의 우회 방법**
```html
<!DOCTYPE html>
<html>
<body>
    <h1>확인: 이 페이지는 window.top과 같은 iframe입니다</h1>
    
    <script>
        // 공격자가 window.top을 조작
        Object.defineProperty(window, 'top', {
            get: function() {
                return window; // window.top을 window로 속임
            },
            configurable: false
        });
    </script>
    
    <!-- 이제 iframe 안에서도 window === window.top이 true가 됨 -->
    <iframe src="https://vulnerable.com/delete-account" 
            style="opacity: 0; position: absolute;"></iframe>
</body>
</html>
```

---

## ✨ 방어 코드 (After — 공격 원리를 알고 설계한 구현)

### 1. X-Frame-Options + CSP frame-ancestors

**Spring Security Configuration**
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // ✅ 방어 1: X-Frame-Options 헤더 설정
            .headers(headers -> headers
                .frameOptions(frameOptions -> frameOptions
                    // DENY: 어떤 도메인이든 iframe으로 임베드 불가능
                    .deny()
                    
                    // 또는 SAMEORIGIN: 같은 출처만 가능
                    // .sameOrigin()
                    
                    // 또는 ALLOW-FROM (deprecated): 특정 도메인만 허용
                    // .allowFrom("https://trusted-domain.com")
                )
                
                // ✅ 방어 2: Content Security Policy의 frame-ancestors
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives(
                        "default-src 'self'; " +
                        "frame-ancestors 'none'; " + // iframe 임베드 완전 금지
                        "script-src 'self'; " +
                        "style-src 'self'; " +
                        "report-uri /api/csp-report"
                    )
                )
            );
        
        return http.build();
    }
}

// 결과:
// X-Frame-Options: DENY
// Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; ...
```

---

### 2. 민감한 기능에 추가 보호

**강화된 Transfer Controller**
```java
@RestController
@RequestMapping("/api")
public class TransferController {
    
    @Autowired
    private TransferService transferService;
    
    // ✅ 방어 1: POST 요청만 허용 (GET 금지)
    @PostMapping("/transfer")
    public ResponseEntity<?> transfer(
            @RequestBody @Valid TransferRequest request,
            HttpServletRequest httpRequest) {
        
        // ✅ 방어 2: Origin 헤더 검증 (CSRF 방지)
        String origin = httpRequest.getHeader("Origin");
        if (!isValidOrigin(origin)) {
            throw new SecurityException("Invalid origin: " + origin);
        }
        
        // ✅ 방어 3: CSRF 토큰 검증
        // (Spring Security @CsrfToken 사용)
        
        // ✅ 방어 4: 추가 인증 요구
        // 민감한 작업은 OTP, 이메일 확인 등 2FA 필수
        String otp = request.getOtp();
        if (!verifyOtp(otp)) {
            throw new SecurityException("OTP 검증 실패");
        }
        
        // ✅ 방어 5: 속도 제한 (Rate Limiting)
        if (!rateLimiter.allowRequest(getCurrentUser())) {
            throw new TooManyRequestsException("너무 많은 송금 시도");
        }
        
        // 송금 실행
        Transfer transfer = transferService.transfer(
            getCurrentUser().getId(),
            request.getRecipientId(),
            request.getAmount()
        );
        
        // ✅ 방어 6: 감사 로그
        auditLog.log(getCurrentUser().getId(), "TRANSFER",
                    Map.of("recipient", request.getRecipientId(),
                           "amount", request.getAmount(),
                           "ip", getClientIp(httpRequest)));
        
        return ResponseEntity.ok(new TransferResponse(transfer.getId()));
    }
    
    private boolean isValidOrigin(String origin) {
        Set<String> allowedOrigins = Set.of(
            "https://banking.example.com",
            "https://app.example.com"
        );
        return allowedOrigins.contains(origin);
    }
    
    private boolean verifyOtp(String otp) {
        // OTP 검증 로직
        User user = getCurrentUser();
        return otpService.verify(user, otp);
    }
    
    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        return ip != null ? ip : request.getRemoteAddr();
    }
}

// CSRF 토큰과 함께 보내는 클라이언트 코드
// const csrfToken = document.querySelector('meta[name="csrf-token"]').content;
// fetch('/api/transfer', {
//     method: 'POST',
//     headers: {
//         'Content-Type': 'application/json',
//         'X-CSRF-Token': csrfToken
//     },
//     body: JSON.stringify({
//         recipientId: 123,
//         amount: 5000,
//         otp: userEnteredOtp
//     })
// });
```

---

### 3. 클라이언트 사이드 방어 (심화)

**안전한 Clickjacking 방지 JavaScript**
```javascript
// ✅ 방어 전략 1: 최상위 윈도우 확인
(function() {
    if (window !== window.top) {
        // iframe 안에 있으면 최상위로 이동
        window.top.location = window.location;
    }
})();

// ✅ 방어 전략 2: 더 견고한 방법 (공격자의 window 조작 우회)
(function() {
    try {
        if (window.self !== window.top) {
            throw new Error("Framed!");
        }
    } catch (e) {
        // 공격자가 접근을 차단했으면 빈 페이지 표시
        document.body.innerHTML = '';
        return;
    }
})();

// ✅ 방어 전략 3: 민감한 기능 클릭 시 추가 확인
document.getElementById('deleteAccountBtn').addEventListener('click', function(e) {
    // 사용자에게 한 번 더 확인
    if (!confirm('정말로 계정을 삭제하시겠습니까? 이 작업은 되돌릴 수 없습니다.')) {
        e.preventDefault();
        return;
    }
    
    // OTP 입력 요구
    const otp = prompt('보안을 위해 OTP를 입력하세요:');
    if (!otp) {
        e.preventDefault();
        return;
    }
    
    // 서버에서 OTP 검증 후 실행
    fetch('/api/verify-otp', {
        method: 'POST',
        body: JSON.stringify({ otp: otp })
    })
    .then(r => r.json())
    .then(data => {
        if (data.valid) {
            // OTP 유효하면 계정 삭제 진행
            document.getElementById('deleteForm').submit();
        } else {
            alert('OTP가 유효하지 않습니다');
            e.preventDefault();
        }
    });
    
    e.preventDefault();
});

// ✅ 방어 전략 4: 마우스 움직임 추적 (Advanced)
let mouseMovements = 0;
let clickPosition = null;

document.addEventListener('mousemove', function(e) {
    mouseMovements++;
});

document.getElementById('sensitiveBtn').addEventListener('click', function(e) {
    clickPosition = { x: e.clientX, y: e.clientY };
    
    // 마우스 움직임이 거의 없으면 봇이나 자동화 도구 의심
    if (mouseMovements < 5) {
        console.warn('Suspicious click detected: no mouse movement');
        e.preventDefault();
        return;
    }
    
    // 클릭 위치가 버튼 경계를 벗어나면 Clickjacking 의심
    const rect = this.getBoundingClientRect();
    if (clickPosition.x < rect.left || clickPosition.x > rect.right ||
        clickPosition.y < rect.top || clickPosition.y > rect.bottom) {
        console.warn('Suspicious click: outside button boundary');
        e.preventDefault();
        return;
    }
});
```

---

### 4. HTML 메타 태그 방어 (구형 브라우저 호환성)

**Thymeleaf Template**
```html
<!DOCTYPE html>
<html>
<head>
    <!-- ✅ 구형 브라우저 호환성을 위한 메타 태그 -->
    <!-- (일부 구형 브라우저에서 X-Frame-Options 대신 인식) -->
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta http-equiv="Content-Security-Policy" 
          content="frame-ancestors 'none'">
    
    <!-- CSRF 토큰 메타 태그 -->
    <meta name="csrf-token" th:content="${_csrf.token}">
    <meta name="csrf-header" th:content="${_csrf.headerName}">
</head>
<body>
    <!-- ✅ 민감한 기능은 버튼 형태가 아니라 확인 단계 거침 -->
    <button id="deleteBtn" onclick="initiateDelete()">계정 삭제</button>
    
    <!-- 확인 모달 (초기 숨김) -->
    <div id="confirmModal" style="display: none;">
        <h2>계정 삭제 확인</h2>
        <p>정말로 계정을 삭제하시겠습니까?</p>
        <p>이 작업은 되돌릴 수 없습니다.</p>
        
        <!-- OTP 입력 -->
        <label>OTP 입력:</label>
        <input type="text" id="otpInput" placeholder="6자리 코드">
        
        <!-- 최종 확인 버튼 -->
        <button onclick="confirmDelete()">정말로 삭제하기</button>
        <button onclick="cancelDelete()">취소</button>
    </div>
    
    <script>
        function initiateDelete() {
            // Step 1: 모달 표시
            document.getElementById('confirmModal').style.display = 'block';
            
            // Step 2: 포커스를 이동 (공격자의 마우스 조작 최소화)
            document.getElementById('otpInput').focus();
        }
        
        function confirmDelete() {
            // Step 3: OTP 검증
            const otp = document.getElementById('otpInput').value;
            if (!otp) {
                alert('OTP를 입력하세요');
                return;
            }
            
            // Step 4: 서버에 요청
            const csrfToken = document.querySelector('meta[name="csrf-token"]').content;
            fetch('/api/delete-account', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({ otp: otp })
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    alert('계정이 삭제되었습니다');
                    window.location.href = '/';
                } else {
                    alert('오류: ' + data.message);
                }
            });
        }
        
        function cancelDelete() {
            document.getElementById('confirmModal').style.display = 'none';
            document.getElementById('otpInput').value = '';
        }
    </script>
</body>
</html>
```

---

## 🔬 공격 원리 분석 (공격자 관점의 내부 동작)

### 공격 시나리오 1: Facebook 좋아요 하이재킹

```
1단계: 공격자가 악성 웹사이트 생성
┌─────────────────────────────────────┐
│ attacker.com/claim-iphone.html
│ 
│ "Click Here to Claim FREE iPhone!"
│ (매력적인 버튼이 보임)
└─────────────────────────────────────┘

2단계: 실제 구조 (숨겨짐)
┌─────────────────────────────────────┐
│ <button style="...">Get iPhone</button>
│ <!-- 그 위에 투명한 iframe 겹침 -->
│ <iframe src="https://facebook.com/share?..."
│         style="opacity: 0; position: absolute;">
│ </iframe>
│
│ 사용자 시점: Get iPhone 버튼만 보임
│ 공격자 시점: 실제로는 Facebook 공유 버튼 위치
└─────────────────────────────────────┘

3단계: 사용자가 클릭
┌─────────────────────────────────────┐
│ 사용자: "Get iPhone" 버튼을 클릭하려 함
│ 실제: 투명 iframe의 Facebook 공유 버튼 클릭
│ 
│ Facebook API 호출:
│ POST /share?message=Check this out!
└─────────────────────────────────────┘

4단계: 광범위한 확산
┌─────────────────────────────────────┐
│ 사용자의 프로필에 자동으로 게시됨:
│ "Check this out! [링크: attacker.com/malware]"
│
│ 사용자의 친구들이 게시물 본다:
│ → 친구들도 클릭
│ → 친구들도 자동으로 공유
│ → Worm 효과로 기하급수적 확산
│
│ 하루 만에 수백만 사용자 영향
└─────────────────────────────────────┘
```

### 공격 시나리오 2: 은행 송금 Clickjacking

```
1단계: 공격 페이지 준비
┌─────────────────────────────────────┐
│ attacker.com/game.html
│ 
│ "조이스틱 게임 플레이"
│ (그림과 설명만 보임)
│
│ 실제로는:
│ <iframe src="https://mybank.com/transfer?
│           recipient_id=attacker&
│           amount=10000"
│         style="opacity: 0; position: absolute;
│                width: 100px; height: 50px;">
│ </iframe>
└─────────────────────────────────────┘

2단계: 사용자가 게임을 플레이하려 클릭
┌─────────────────────────────────────┐
│ 사용자: "조이스틱" 영역을 클릭
│ 
│ 실제로: 은행 iframe의 "확인" 버튼 클릭
│ 
│ 은행의 JavaScript:
│ - 현재 사용자의 세션 쿠키 사용
│ - CSRF 토큰이 이미 페이지에 포함됨
│ - 송금 요청 제출
└─────────────────────────────────────┘

3단계: 송금 완료 (사용자 모르게)
┌─────────────────────────────────────┐
│ POST /transfer
│ recipient: attacker
│ amount: 10000
│ csrf_token: (페이지에 자동으로 포함됨)
│
│ 응답:
│ {"status": "success", "transaction_id": "TXN123"}
│
│ 사용자의 계좌에서 1만원이 사라짐
│ 공격자의 계좌에 입금됨
└─────────────────────────────────────┘

4단계: 대규모 공격
┌─────────────────────────────────────┐
│ 공격자가 광고 네트워크에서 게임 클릭 광고 구매
│ → 수백만 명이 공격 페이지 방문
│ → 각각 일부가 iframe 영역 클릭
│ → 수천 건의 송금 발생
│ → 공격자가 모든 송금의 합계 횡령
└─────────────────────────────────────┘
```

---

## 💻 실전 실험 (취약점 재현 → 공격 → 방어 검증)

### 실험 1: X-Frame-Options 테스트

**Step 1: 취약한 서버 구성**
```java
@Configuration
public class VulnerableConfig implements WebMvcConfigurer {
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new InterceptorAdapter() {
            @Override
            public boolean preHandle(HttpServletRequest request,
                                    HttpServletResponse response,
                                    Object handler) throws Exception {
                // X-Frame-Options 헤더 없음
                return true;
            }
        });
    }
}

// localhost:8080/vulnerable
// → X-Frame-Options 헤더 없음
```

**Step 2: 공격 HTML 생성**
```html
<!-- attack.html -->
<!DOCTYPE html>
<html>
<head>
    <style>
        .button {
            padding: 50px;
            font-size: 40px;
            background: #4CAF50;
            color: white;
            border: none;
            cursor: pointer;
            position: relative;
        }
        
        iframe {
            position: absolute;
            top: 100px;
            left: 50px;
            width: 200px;
            height: 60px;
            opacity: 0;
            z-index: 999;
            border: none;
        }
    </style>
</head>
<body>
    <h1>클릭해서 상품 받기!</h1>
    <button class="button">
        여기를 클릭하세요
        <!-- 투명 iframe: 취약한 서버의 중요 페이지 -->
        <iframe src="http://localhost:8080/vulnerable"></iframe>
    </button>
</body>
</html>
```

**Step 3: 공격 확인**
```bash
# attack.html을 다른 포트에서 호스팅
python -m http.server 8081 --directory .

# 브라우저에서 접속
http://localhost:8081/attack.html

# "여기를 클릭하세요" 버튼 클릭
# 실제로는 iframe의 페이지와 상호작용됨
# 개발자 도구 Network 탭에서 요청 확인 가능
```

**Step 4: 방어 적용**
```java
@Configuration
@EnableWebSecurity
public class SecureConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .headers(headers -> headers
                .frameOptions(frameOptions -> frameOptions.deny())
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives("frame-ancestors 'none'")
                )
            );
        return http.build();
    }
}

// 응답 헤더:
// X-Frame-Options: DENY
// Content-Security-Policy: frame-ancestors 'none'
```

**Step 5: 방어 검증**
```bash
# 동일한 공격 HTML로 테스트
http://localhost:8081/attack.html

# 결과: iframe 콘텐츠 로드 실패
# 브라우저 콘솔:
# Refused to frame 'http://localhost:8080/vulnerable' because an ancestor violates the following Content Security Policy directive: "frame-ancestors 'none'".
```

---

### 실험 2: Clickjacking 시뮬레이션

**Step 1: 민감한 기능**
```java
@RestController
@RequestMapping("/api")
public class AccountController {
    
    @PostMapping("/delete-account")
    public ResponseEntity<?> deleteAccount() {
        // 민감한 기능: 계정 삭제
        User user = getCurrentUser();
        
        // ❌ 방어 없음 (실험용 취약한 코드)
        userRepository.delete(user);
        
        return ResponseEntity.ok("계정이 삭제되었습니다");
    }
}
```

**Step 2: 공격 시뮬레이션**
```html
<!-- clickjacking-attack.html -->
<!DOCTYPE html>
<html>
<body>
    <h1>게임 플레이</h1>
    <button id="gameBtn" style="padding: 100px; font-size: 40px;">
        게임 시작
    </button>
    
    <!-- 투명 iframe: 취약한 API 호출 -->
    <iframe id="hiddenFrame" src="about:blank" 
            style="opacity: 0; position: absolute; width: 1px; height: 1px;">
    </iframe>
    
    <script>
        document.getElementById('gameBtn').addEventListener('click', function() {
            // 게임 버튼 클릭 시 실제로는 iframe에서 API 호출
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = 'http://localhost:8080/api/delete-account';
            form.target = 'hiddenFrame';
            document.body.appendChild(form);
            form.submit();
            
            alert('감사합니다!');
        });
    </script>
</body>
</html>
```

**Step 3: 공격 실행**
```bash
# 사용자가 이 HTML에 접속하고 "게임 시작" 버튼 클릭
# → 계정이 삭제됨 (사용자 모르게)
```

**Step 4: 방어 적용**
```java
@Configuration
@EnableWebSecurity
public class SecureConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // 1. iframe 임베드 방지
            .headers(headers -> headers
                .frameOptions(frameOptions -> frameOptions.deny())
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives("frame-ancestors 'none'")
                )
            )
            
            // 2. CSRF 보호
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            )
            
            // 3. CORS 제한
            .cors(cors -> cors.configurationSource(corsSource()));
        
        return http.build();
    }
    
    private CorsConfigurationSource corsSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("https://mysite.com"));
        config.setAllowedMethods(List.of("GET", "POST"));
        config.setAllowCredentials(true);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", config);
        return source;
    }
}
```

**Step 5: 방어 검증**
```
1. iframe 차단:
   iframe src="..." → Content Security Policy 위반으로 로드 실패

2. CSRF 토큰:
   POST /api/delete-account → CSRF 토큰이 없으면 거부

3. CORS 정책:
   다른 도메인에서의 요청 → 사전 요청(preflight) 실패 후 실제 요청 차단
```

---

## 📊 공격 성공 조건 vs 방어 성공 조건 비교

| 구분 | 공격 성공 조건 | 방어 성공 조건 |
|------|---|---|
| **iframe 임베드** | X-Frame-Options 없음, frame-ancestors 설정 없음 | X-Frame-Options: DENY + CSP frame-ancestors 'none' |
| **민감한 기능** | GET/POST로 상태 변경 가능 | POST 요청만 허용, 추가 인증(OTP/2FA) 필수 |
| **CSRF 보호** | CSRF 토큰 검증 없음 | Spring Security CSRF 토큰 + 검증 |
| **자동화 공격** | 마우스 움직임, 시간 검증 없음 | 사용자 상호작용 감지, Rate Limiting |
| **Client-side 방어** | window.top 검사만 함 | 다중 계층 방어 + OTP 필수 |

---

## ⚖️ 트레이드오프 (보안 강화 vs 사용성/성능)

### 1. X-Frame-Options: DENY vs SAMEORIGIN

**DENY (가장 안전)**
```
X-Frame-Options: DENY

장점:
- Clickjacking 100% 방지
- 구현 가장 간단

단점:
- 같은 도메인에서도 iframe 사용 불가능
- 내부 시스템 통합 어려움 (예: 대시보드에 여러 프레임 포함)
```

**SAMEORIGIN (균형)**
```
X-Frame-Options: SAMEORIGIN

장점:
- 같은 도메인 iframe 허용
- 내부 통합 가능

단점:
- 서브도메인 공격 위험 (같은 도메인이므로)
- Clickjacking 완벽하지 않음
```

### 2. 민감한 기능의 추가 인증

**매우 강화 (2FA)**
```
장점:
- 비인가 작업 거의 불가능
- 보안 최우선

단점:
- 사용성 저하 (매번 OTP 입력)
- 이탈률 증가
- 고객 지원 비용 증가
```

**균형 (중요도별 인증)**
```
선택 기준:
- 계정 삭제: OTP 필수
- 송금: OTP 필수
- 프로필 수정: OTP 선택
- 배경화면 변경: OTP 불필요

이유:
- 돌이킬 수 없는 작업만 강화
- 일반 기능은 편리성 유지
```

---

## 📌 핵심 정리

### Clickjacking 방어의 3단계

```
1단계: iframe 임베드 차단
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none'

2단계: 상태 변경 요청 보호
- POST 요청만 허용 (GET으로 상태 변경 금지)
- CSRF 토큰 검증
- Origin 헤더 검증

3단계: 민감한 기능에 추가 보호
- 2FA (One-Time Password)
- 사용자 상호작용 확인
- Rate Limiting
```

### 브라우저 헤더 우선순위

```
브라우저가 다음 순서로 확인:
1. X-Frame-Options 헤더
   (가장 우선순위 높음, 즉시 검사)

2. Content-Security-Policy frame-ancestors
   (X-Frame-Options 없을 때 적용)

3. Client-side JavaScript 검사
   (서버 헤더가 없을 때만 신뢰)
   
→ 항상 1번 헤더를 명시할 것!
```

---

## 🤔 생각해볼 문제 (+ 해설)

### Q1. X-Frame-Options: SAMEORIGIN에서 서브도메인 공격이 가능한가?

**해설**
```
예시 도메인 구조:
main.example.com (메인 서비스)
shop.example.com (쇼핑몰)
admin.example.com (관리자 페이지)

X-Frame-Options: SAMEORIGIN 설정

메인 서비스: https://main.example.com/transfer
- "same-origin" 확인: example.com 부모도메인 같음 ✅
- shop.example.com에서 iframe 가능

공격 시나리오:
1. 공격자가 shop.example.com을 해킹 또는 제어
2. admin.example.com/delete-admin-account를 iframe으로 임베드
3. SAMEORIGIN 검사: example.com == example.com (부모 도메인 같음) ✅
4. Clickjacking 성공!

원인:
- SAMEORIGIN은 공개 서픽스만 비교 (예: .com)
- 서브도메인 간 신뢰도 가정
- 하지만 서브도메인이 해킹되면 위험

방어:
```
X-Frame-Options: DENY
또는
X-Frame-Options: ALLOW-FROM https://specific-subdomain.example.com
(deprecated, 권장하지 않음)

현대 방식:
Content-Security-Policy: frame-ancestors 'self'
// 'self'는 정확한 도메인 (서브도메인 포함) 모두 적용
// 하지만 신뢰할 수 있는 서브도메인만 사전 검증 필요
```
```

---

### Q2. window.top 검사를 우회할 수 있는가?

**해설**
```
일반적인 코드:
```javascript
if (window !== window.top) {
    window.top.location = window.location;
}
```

공격자의 우회 방법 1: window 객체 조작
```javascript
// 공격자의 iframe에서
Object.defineProperty(window, 'top', {
    get: function() { return window; },
    configurable: false
});
// 이제 window.top === window (항상 true)
```

공격자의 우회 방법 2: try-catch 무시
```javascript
try {
    window.top.location;
} catch (e) {
    // 에러 발생: top에 접근 불가능
    // 하지만 catch 블록에서 아무것도 안 함
}
```

더 견고한 방어:
```javascript
(function() {
    try {
        // 1단계: self와 top이 다른가?
        if (window.self !== window.top) {
            throw new Error("Framed");
        }
        
        // 2단계: top에서 location 변경 가능한가?
        window.top.location.href = window.location.href;
        
        // 3단계: 여전히 여기에 있으면 top이 변경되지 않았단 뜻
        // (공격자가 차단함)
        document.body.innerHTML = '';
        
    } catch (e) {
        // 공격자가 차단했으므로 빈 페이지 표시
        document.body.innerHTML = '';
    }
})();
```

하지만 최선의 방어:
```
서버 헤더에만 의존
X-Frame-Options: DENY
→ 브라우저 수준에서 iframe 로드 자체 차단
→ JavaScript 실행 기회 없음
```

결론: JavaScript 방어는 보조 수단일 뿐, 서버 헤더가 필수
```

---

### Q3. CSRF 토큰이 있어도 Clickjacking이 가능한가?

**해설**
```
예시: 은행 송금 페이지

HTML:
```html
<form method="POST" action="/transfer">
    <input type="hidden" name="csrf_token" value="abc123xyz">
    <!-- CSRF 토큰이 이미 페이지에 포함됨! -->
    
    <input type="text" name="recipient" placeholder="받는 사람">
    <input type="text" name="amount" placeholder="금액">
    <button type="submit">송금</button>
</form>
```

Clickjacking 공격:
```html
<iframe src="https://bank.com/transfer" 
        style="opacity: 0; position: absolute; width: 100%; height: 100%;">
</iframe>

<!-- 받는 사람: attacker_account -->
<!-- 금액: 10000 -->
<!-- CSRF 토큰: iframe에서 자동으로 로드됨 -->
<!-- → 모든 필요한 정보가 있으므로 송금 가능! -->
```

왜 가능한가?
1. CSRF 토큰은 같은 출처에서만 유효
2. iframe도 같은 출처 (같은 도메인)
3. 토큰이 자동으로 포함됨
4. 클릭하면 form이 제출됨

방어 방법:
```
1단계: X-Frame-Options (iframe 차단)
X-Frame-Options: DENY
→ iframe이 로드되지 않음
→ CSRF 토큰을 볼 수 없음

2단계: 추가 인증 (2FA/OTP)
→ iframe 안에서는 OTP 입력 어려움
→ 사용자가 인식하고 거부 가능

3단계: Double-Submit Cookie
→ CSRF 토큰과 쿠키 값이 일치해야 함
→ 클라이언트 코드에서 명시적으로 전송

예:
```javascript
fetch('/api/transfer', {
    method: 'POST',
    headers: {
        'X-CSRF-Token': getCsrfTokenFromDom(),
        'X-CSRF-Token-Cookie': getCookieValue()
    },
    body: JSON.stringify(data)
});
```

iframe 안에서는 두 값이 일치하지 않을 가능성 높음
```

결론: CSRF 토큰만으로는 Clickjacking 방어 불가능
→ X-Frame-Options + 추가 인증 필수
```

---

### Q4. Rate Limiting이 Clickjacking을 어떻게 방지하는가?

**해설**
```
Clickjacking의 특성:
- 사용자가 한 번 클릭하면 하나의 작업 실행
- 여러 번 반복하려면 여러 페이지 방문 필요
- 다른 사용자의 작업과 섞임

Rate Limiting의 효과:
```
1시간에 최대 5회 송금 허용
↓
공격자가 Clickjacking으로 50명을 해킹하려 함
↓
각 사용자마다 5회씩만 가능
→ 최대 250건 송금 (50 × 5)
→ 그 이상은 차단됨

더 나은 Rate Limiting:
```java
@PostMapping("/transfer")
public ResponseEntity<?> transfer(@RequestBody TransferRequest req) {
    // 1. IP 기반 제한
    if (!rateLimiter.checkIpLimit(getClientIp())) {
        throw new TooManyRequestsException();
    }
    
    // 2. 사용자 기반 제한
    if (!rateLimiter.checkUserLimit(getCurrentUser())) {
        throw new TooManyRequestsException();
    }
    
    // 3. 이상 거래 감지 (같은 수신자에게 여러 건)
    if (!fraudDetector.isNormalTransaction(req)) {
        // OTP 재인증 요구
        throw new RequireOtpVerification();
    }
    
    // 4. 새로운 기기에서의 송금
    if (!deviceService.isKnownDevice(getCurrentUser())) {
        // 이메일 확인 필수
        throw new RequireEmailVerification();
    }
    
    // 5. 새로운 수신자에게 처음 송금
    if (!hasTransferredBefore(getCurrentUser(), req.getRecipientId())) {
        // 대기 시간 필수 (예: 24시간)
        throw new RequireWaitingPeriod("Please wait 24 hours before sending to new recipient");
    }
    
    // 모든 검사 통과하면 송금
    performTransfer(req);
    return ResponseEntity.ok("송금 완료");
}
```

하지만 근본적 한계:
- Rate Limiting은 공격 속도를 늦출 뿐
- Clickjacking 자체를 막지는 못함
- X-Frame-Options와 함께 사용해야 함
```

<div align="center">

**[⬅️ 이전: CSP](./03-content-security-policy.md)** | **[홈으로 🏠](../README.md)** | **[다음: 보안 HTTP 헤더 완전 가이드 ➡️](./05-security-http-headers.md)**

</div>
