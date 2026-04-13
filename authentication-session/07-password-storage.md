# 비밀번호 저장 (Password Hashing)
---

## 🎯 핵심 질문
비밀번호 데이터베이스가 유출되면 모든 사용자가 위험에 빠진다. MD5나 SHA-1로 해시하면 충분한가? Rainbow Table은 무엇이고, Bcrypt와 Argon2의 내부 원리는 무엇인가?

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

### LinkedIn 데이터 유출 (2012, 650만 계정)
LinkedIn은 SHA-1로 비밀번호를 해시했었다:
1. 650만 개의 사용자 계정 데이터 유출
2. 공격자가 약 90%의 비밀번호를 크래킹 (몇 시간 내)
3. SHA-1은 약 10년 전부터 취약점이 알려짐
4. 오프라인 크래킹: GPU를 사용하여 초당 수십억 개의 해시 검증

### Adobe 데이터 유출 (2013, 1,500만 계정)
Adobe는 약한 암호화를 사용했었다:
1. 1,500만 개 계정 유출
2. 비밀번호가 약한 암호화로 저장됨 (DES 기반)
3. 해독 시간: 단 몇 분
4. 거의 모든 비밀번호 복구됨

### Yahoo 데이터 유출 (2013-2014, 30억 계정)
Yahoo 최대 규모 유출:
1. 30억 개 계정 (지구 인구의 40%)
2. bcrypt를 사용했지만, 키 리더 버그로 일부 계정 크래킹 가능
3. 완벽한 보호도 구현 결함으로 인해 무너질 수 있음

### Equifax 데이터 유출 (2017, 1.47억 계정)
신용 정보 회사 Equifax:
1. 1.47억 개의 사회보장번호, 생년월일 등 유출
2. bcrypt를 사용했지만, 레거시 시스템에서 평문 저장된 부분 발견
3. 암호화 전략이 시간에 따라 변경되면서 일관성 없음

## 😱 취약한 코드 (Before — 원리를 모를 때의 구현)

### 1. MD5/SHA-1로 해시하는 경우 (Rainbow Table 취약)

```java
// ❌ 취약한 코드: MD5/SHA-1 사용
@Service
public class VulnerablePasswordService {
    
    @Autowired
    private UserRepository userRepository;
    
    public String hashPassword_MD5(String password) {
        // ❌ MD5는 콜리전(충돌)에 취약, 2004년부터 보안성 의문
        // ❌ 솔트도 없음
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }
    
    public String hashPassword_SHA1(String password) {
        // ❌ SHA-1도 2010년부터 약점 알려짐
        // ❌ 역시 솔트 없음
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] hash = md.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }
    
    public void registerUser(String username, String password) {
        User user = new User();
        user.setUsername(username);
        
        // ❌ 위험: 솔트 없이 MD5/SHA-1로 저장
        user.setPasswordHash(hashPassword_MD5(password));
        // 또는 user.setPasswordHash(hashPassword_SHA1(password));
        
        userRepository.save(user);
    }
}

// 공격 시나리오: Rainbow Table
// 1. 공격자가 비밀번호 1~10억 개의 MD5 해시 미리 계산
//    password123 → md5(password123) = 482c811da5d5b4bc6d497ffa98491e38
//
// 2. 데이터베이스에서 비밀번호 해시 탈취
//    사용자: john, 해시: 482c811da5d5b4bc6d497ffa98491e38
//
// 3. Rainbow Table에서 역검색 (O(1) 시간)
//    482c811da5d5b4bc6d497ffa98491e38 → password123
//
// 4. john의 비밀번호 = password123 (크래킹 완료!)

// Rainbow Table 크래킹 성공 확률
// MD5 사전 크기: 14억 (rockyou.txt + variations)
// 일반적인 비밀번호 포함 확률: 90%+
// 크래킹 시간: 밀리초 단위
```

### 2. 솔트 없이 SHA-256 사용

```java
// ❌ 취약한 코드: 솔트 없는 SHA-256
@Service
public class WeakSHA256Service {
    
    public String hashPasswordWithoutSalt(String password) {
        // ❌ 솔트가 없음
        // 같은 비밀번호 → 항상 같은 해시
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(password.getBytes());
        return Hex.encodeHexString(hash);
    }
    
    public void registerUser(String username, String password) {
        User user = new User();
        user.setUsername(username);
        user.setPasswordHash(hashPasswordWithoutSalt(password));
        
        userRepository.save(user);
    }
}

// 공격 시나리오: 같은 비밀번호 탐지
// 데이터베이스:
// john: sha256(password123) = ef92b778bafe771e89245d171bafdfb...
// jane: sha256(password456) = 8d969eef6ecad3c29a3a873fba5443f...
// admin: sha256(password123) = ef92b778bafe771e89245d171bafdfb...
//
// 공격자가 기록
// john과 admin은 같은 해시 → 같은 비밀번호!
//
// john의 비밀번호를 크래킹하면 admin도 자동으로 알 수 있음

// 또한 자주 사용되는 비밀번호를 사전에 해시해서 매칭
// password123 해시를 미리 계산해놓고 찾으면:
// john, admin, 그 외 100만 명의 계정이 이 비밀번호 사용 중
```

### 3. 약한 비밀번호 해시 설정

```java
// ❌ 취약한 코드: Spring Security의 약한 설정
@Configuration
public class WeakPasswordEncoderConfig {
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        // ❌ pbkdf2로 iterations이 너무 적음 (기본 185,000)
        // ❌ 또는 더 약한 알고리즘 사용
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
        // 기본값이 bcrypt이지만 iterations가 설정되지 않을 수 있음
    }
}

// SHA-256을 반복하는 경우
public String naiveIterativeHash(String password, int iterations) {
    String hash = password;
    
    // ❌ iterations가 너무 적음 (1000회 미만)
    for (int i = 0; i < iterations; i++) {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        hash = Hex.encodeHexString(md.digest(hash.getBytes()));
    }
    
    return hash;
}

// 문제:
// iterations = 1000일 때
// GPU로 초당 수십억 해시 계산 가능
// 10억 비밀번호 × 1000 iterations = 10^12 해시
// GPU: 초당 수십억 → 약 1000초 (17분) 안에 모두 크래킹

// iterations = 100,000+일 때
// 같은 계산이 1700,000초 (약 5개월)이 필요
// 따라서 부실 보호
```

## ✨ 방어 코드 (After — 공격 원리를 알고 설계한 구현)

### 1. Bcrypt 안전한 구현

```java
// ✅ 안전한 코드: Bcrypt 사용
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class SecurePasswordEncoderConfig {
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        // ✅ Bcrypt: 가장 권장되는 알고리즘 (2004년 이후)
        // ✅ 기본 strength: 10 (2^10 = 1024 iterations)
        // ✅ Java에서는 최대 31까지 가능 (2^31 iterations)
        // ✅ 자동으로 솔트 생성 및 포함
        return new BCryptPasswordEncoder(12);  // strength = 12 (권장)
    }
}

// Bcrypt의 내부 구조
// $2a$12$someSaltHereAndHashHere
// $2a$ = Bcrypt 버전
// $12$ = Cost factor (2^12 iterations = 4096)
// someSaltHereAndHashHere = 22자 솔트 + 31자 해시

@Service
public class SecureBcryptPasswordService {
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Autowired
    private UserRepository userRepository;
    
    public void registerUser(String username, String password) {
        User user = new User();
        user.setUsername(username);
        
        // ✅ 1. Bcrypt로 비밀번호 해시
        // ✅ 2. 솔트 자동 생성 (내부)
        // ✅ 3. iterations 설정된 상태
        String bcryptHash = passwordEncoder.encode(password);
        // 예: $2a$12$abcd1234...
        
        user.setPasswordHash(bcryptHash);
        userRepository.save(user);
    }
    
    public boolean validatePassword(String rawPassword, String bcryptHash) {
        // ✅ matches()로 안전하게 비교 (타이밍 공격 방지)
        return passwordEncoder.matches(rawPassword, bcryptHash);
    }
}

// Bcrypt의 강점
// 1. 솔트: 22자, 자동 생성, 해시에 포함
// 2. 반복: Cost factor로 시간 조절 가능
// 3. 타이밍 공격 방지: 항상 일정한 시간 소요
// 4. GPU 저항: 메모리 사용으로 GPU 병렬 처리 비효율적

// Bcrypt 크래킹 시간 (Cost 12, GPU 사용)
// 초당 가능한 해시: 약 100,000~1,000,000개
// 전체 비밀번호 1억 개 크래킹:
// 100,000 per sec → 1,000초 (약 17분)
// 하지만 가능 비밀번호는 약 1,000만 개 (자주 사용되는 것)
// 따라서 실제로는 몇 분 내 90% 이상 크래킹 가능
// 
// 해결: Cost를 13~14로 상향 (4배 시간 증가)
```

### 2. Argon2 (메모리 하드 함수)

```java
// ✅ 안전한 코드: Argon2 사용 (가장 강함)
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

@Configuration
public class SecureArgon2Config {
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        // ✅ Argon2: 메모리 하드 함수 (GPU 저항력 최강)
        // ✅ 메모리: 65536 KB (64 MB)
        // ✅ 시간: 2 iterations
        // ✅ 병렬도: 1 (병렬화 없음)
        return new Argon2PasswordEncoder(
            65536,   // memory (KB)
            65536,   // saltLength
            1,       // parallelism
            60000,   // hashLength (ms)
            3        // version (Argon2id)
        );
    }
}

// Argon2의 내부 원리
// 1. 메모리 사용: 64MB를 필요로 함
//    → GPU는 메모리 병렬화 어려움
//    → GPU 어택 저항력 높음
//
// 2. 시간 비용: 여러 번 반복
//    → 계산 시간 증가
//
// 3. 병렬도: CPU 코어 활용
//    → 공격자가 병렬화로 가속 어려움

@Service
public class SecureArgon2PasswordService {
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    public void registerUser(String username, String password) {
        User user = new User();
        user.setUsername(username);
        
        // ✅ Argon2로 해시 (내부적으로 솔트 생성)
        String argon2Hash = passwordEncoder.encode(password);
        // 예: $argon2id$v=19$m=65536,t=3,p=1$...
        
        user.setPasswordHash(argon2Hash);
        userRepository.save(user);
    }
    
    public boolean validatePassword(String rawPassword, String argon2Hash) {
        return passwordEncoder.matches(rawPassword, argon2Hash);
    }
}

// Argon2 vs Bcrypt 크래킹 시간 비교
// CPU 기준 (1억 비밀번호):
// Bcrypt (cost 12): 1시간
// Argon2 (64MB): 약 2주 (메모리 제약)
//
// GPU 기반:
// Bcrypt (cost 12): 약 10분 (병렬 처리 가능)
// Argon2: 약 1개월 (메모리 병렬화 어려움)
```

### 3. PasswordEncoder 업그레이드 전략

```java
// ✅ 안전한 코드: DelegatingPasswordEncoder로 업그레이드
@Configuration
public class PasswordEncoderUpgradeConfig {
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        // ✅ DelegatingPasswordEncoder: 여러 인코더 지원
        String idForEncode = "bcrypt";  // 새 비밀번호는 bcrypt로
        
        Map<String, PasswordEncoder> encoders = new HashMap<>();
        encoders.put(idForEncode, new BCryptPasswordEncoder(12));
        encoders.put("bcrypt", new BCryptPasswordEncoder(12));
        encoders.put("sha256", new StandardPasswordEncoder());  // 레거시
        encoders.put("pbkdf2", Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8());
        
        return new DelegatingPasswordEncoder(idForEncode, encoders);
    }
}

// DelegatingPasswordEncoder의 동작 원리
// 저장된 해시: {bcrypt}$2a$12$abcd1234...
//             {sha256}...
//             {pbkdf2}...
//
// 1. 해시의 {prefix}를 읽음
// 2. 해당 인코더 선택
// 3. 검증

@Service
public class PasswordUpgradeService {
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Autowired
    private UserRepository userRepository;
    
    public void upgradePasswordIfNeeded(String username, String rawPassword) {
        User user = userRepository.findByUsername(username).orElse(null);
        
        if (user != null && passwordEncoder.matches(rawPassword, user.getPasswordHash())) {
            // ✅ 로그인 성공
            
            // ✅ 해시가 최신 알고리즘인지 확인
            if (needsUpgrade(user.getPasswordHash())) {
                // 레거시 해시 (SHA-256 등) 발견
                
                // ✅ 새로운 Bcrypt로 다시 해시
                user.setPasswordHash(passwordEncoder.encode(rawPassword));
                userRepository.save(user);
                
                System.out.println("비밀번호 해시가 업그레이드되었습니다");
            }
        }
    }
    
    private boolean needsUpgrade(String hash) {
        // 해시가 {bcrypt}로 시작하지 않으면 업그레이드 필요
        return !hash.startsWith("{bcrypt}");
    }
}

// 업그레이드 전략
// 1. 기존: SHA-256 (약함)
// 2. 사용자 로그인 시: 레거시 해시 검증 (DelegatingPasswordEncoder)
// 3. 로그인 성공 시: 새 Bcrypt로 업그레이드
// 4. 점진적으로 모든 사용자 업그레이드
//    → 강제 업그레이드 없음 (로그인 안 하는 사용자도 있음)
```

### 4. 타이밍 공격 방지

```java
// ❌ 취약한 코드: 타이밍 공격 취약
public boolean isPasswordCorrect(String rawPassword, String storedHash) {
    String computedHash = hashPassword(rawPassword);
    
    // ❌ 문제: 첫 자리부터 다르면 빨리 반환
    if (computedHash.equals(storedHash)) {
        return true;
    } else {
        return false;
    }
    
    // 타이밍 분석으로 비밀번호 추론 가능
    // 올바른 비밀번호: 100ms (완전히 일치할 때까지 비교)
    // 틀린 비밀번호 (첫자 다름): 1ms
    // 공격자가 타이밍으로 올바른 첫자 찾음
}

// ✅ 안전한 코드: 타이밍 공격 방지
@Service
public class TimingSafePasswordService {
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    public boolean validatePasswordSafely(String rawPassword, String storedHash) {
        // ✅ PasswordEncoder.matches()는 타이밍 공격 방지
        // 항상 일정한 시간 소요 (상수 시간)
        
        return passwordEncoder.matches(rawPassword, storedHash);
    }
    
    // PasswordEncoder.matches() 내부 구현
    // 1. 해시 길이를 미리 알 수 있음
    // 2. 모든 비교 연산을 수행 (초기 탈출 X)
    // 3. 잘못된 비밀번호도 완전히 검증
    // 4. 타이밍 일정
}

// Java에서 타이밍 안전 비교
public class TimingSafeComparison {
    
    public static boolean safeEquals(String a, String b) {
        if (a == null || b == null) {
            return a == b;
        }
        
        // ✅ 길이가 같지 않으면 특수 처리
        // 하지만 모든 경우에 시간 소요
        byte[] aBytes = a.getBytes(StandardCharsets.UTF_8);
        byte[] bBytes = b.getBytes(StandardCharsets.UTF_8);
        
        int result = 0;
        // ✅ 항상 모든 바이트 비교 (길이만큼)
        for (int i = 0; i < Math.min(aBytes.length, bBytes.length); i++) {
            result |= aBytes[i] ^ bBytes[i];
        }
        
        // 길이가 다른 경우도 반영
        result |= aBytes.length ^ bBytes.length;
        
        return result == 0;
    }
}
```

## 🔬 공격 원리 분석 (공격자 관점의 내부 동작)

### Rainbow Table 공격

```
┌─────────────────────────────────────┐
│ Rainbow Table 생성 (사전 구축)       │
├─────────────────────────────────────┤
│ 1. 일반적인 비밀번호 1,000,000개    │
│                                      │
│ password123 → md5(...) = 482c811da.. │
│ password456 → md5(...) = 25f9e794... │
│ password789 → md5(...) = 25f9e794... │
│ ...                                   │
│                                      │
│ 테이블 크기: ~50GB                   │
│                                      │
│ 구축 시간: 약 1주                    │
└─────────────────────────────────────┘

┌─────────────────────────────────────┐
│ 데이터 유출 후 크래킹                 │
├─────────────────────────────────────┤
│ 1. 데이터베이스 탈취                  │
│    user: 482c811da5d5b4bc6d497ffa...│
│                                      │
│ 2. Rainbow Table에서 역검색          │
│    482c811da5d5b4bc6d497ffa... = ?  │
│                                      │
│ 3. O(1) 검색: 밀리초 단위 결과        │
│    → password123                     │
│                                      │
│ 4. 비밀번호 크래킹 완료!              │
│    (GPU 또는 병렬화 불필요)          │
│                                      │
│ 크래킹 성공률: 90%+                  │
└─────────────────────────────────────┘

✅ 솔트가 있으면 Rainbow Table 무용지물
각 비밀번호마다 다른 솔트 → 해시 달라짐
MD5(password123 + salt1) ≠ MD5(password123 + salt2)
Rainbow Table의 사전 구축 불가능
```

### GPU 기반 해시 크래킹

```
┌──────────────────────────────────┐
│ Bcrypt (Cost 12) vs GPU          │
├──────────────────────────────────┤
│ 초당 해시 계산: 약 100,000~1,000,000개
│                                   │
│ 1,000,000 비밀번호 크래킹:         │
│ 1,000,000 / 1,000,000 = 1초      │
│                                   │
│ 실제 사용 비밀번호 추정: 약 1,000만개
│ (rockyou.txt 크기)               │
│ 1,000만 / 1,000,000 = 10초       │
│                                   │
│ 90% 이상 크래킹: 약 1분          │
└──────────────────────────────────┘

┌──────────────────────────────────┐
│ Argon2 (메모리 64MB) vs GPU       │
├──────────────────────────────────┤
│ GPU 메모리 부족:                   │
│ - GPU당 메모리: 4GB~24GB          │
│ - 동시 실행: 4GB / 64MB = 64개   │
│                                   │
│ CPU 병렬화보다 느림:              │
│ - CPU: 수천 코어 활용 가능        │
│ - GPU: Argon2 병렬화 어려움       │
│                                   │
│ 결과: CPU 기반이 더 빠름          │
│ 크래킹 시간: 몇 주~몇 개월        │
└──────────────────────────────────┘
```

## 💻 실전 실험 (취약점 재현 → 공격 → 방어 검증)

### 실험 1: MD5 vs Bcrypt 크래킹 시간

```java
@Test
public void testMD5CrackingSpeed() {
    String password = "password123";
    
    // ❌ MD5 해시 생성
    MessageDigest md = MessageDigest.getInstance("MD5");
    byte[] hash = md.digest(password.getBytes());
    String md5Hash = Hex.encodeHexString(hash);
    
    // 크래킹 시뮬레이션
    long startTime = System.currentTimeMillis();
    String[] commonPasswords = loadCommonPasswords();  // 1,000만 개
    
    for (String candidate : commonPasswords) {
        MessageDigest md2 = MessageDigest.getInstance("MD5");
        String candidateHash = Hex.encodeHexString(md2.digest(candidate.getBytes()));
        
        if (candidateHash.equals(md5Hash)) {
            long endTime = System.currentTimeMillis();
            System.out.println("MD5 크래킹 시간: " + (endTime - startTime) + "ms");
            break;
        }
    }
    // 결과: ~1,000ms (1초)
}

@Test
public void testBcryptCrackingSpeed() {
    String password = "password123";
    
    // ✅ Bcrypt 해시 생성
    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
    String bcryptHash = encoder.encode(password);
    
    // 크래킹 시뮬레이션
    long startTime = System.currentTimeMillis();
    String[] commonPasswords = loadCommonPasswords();  // 1,000만 개
    
    for (String candidate : commonPasswords) {
        if (encoder.matches(candidate, bcryptHash)) {
            long endTime = System.currentTimeMillis();
            System.out.println("Bcrypt 크래킹 시간: " + (endTime - startTime) + "ms");
            break;
        }
    }
    // 결과: ~100,000ms (100초) - MD5의 100배 느림!
}
```

### 실험 2: 솔트의 효과

```java
@Test
public void testRainbowTableWithoutSalt() {
    // ❌ 솔트 없음
    String password = "password123";
    MessageDigest md = MessageDigest.getInstance("MD5");
    String hash1 = Hex.encodeHexString(md.digest(password.getBytes()));
    
    md = MessageDigest.getInstance("MD5");
    String hash2 = Hex.encodeHexString(md.digest(password.getBytes()));
    
    // 같은 비밀번호 → 같은 해시
    assertEquals(hash1, hash2);
    
    // Rainbow Table에서 직접 찾을 수 있음
}

@Test
public void testSaltEffectiveness() {
    // ✅ 솔트 있음
    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
    
    String password = "password123";
    String hash1 = encoder.encode(password);
    String hash2 = encoder.encode(password);
    
    // 같은 비밀번호 → 다른 해시 (다른 솔트)
    assertNotEquals(hash1, hash2);
    
    // 하지만 둘 다 같은 비밀번호로 검증됨
    assertTrue(encoder.matches(password, hash1));
    assertTrue(encoder.matches(password, hash2));
}
```

### 실험 3: 업그레이드 전략

```java
@SpringBootTest
public class PasswordUpgradeTest {
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Autowired
    private UserRepository userRepository;
    
    @Test
    public void testPasswordUpgrade() {
        // 1. 레거시 SHA-256 해시
        String legacySHA256 = "5e884898da28047151d0e56f8dc6292...";  // SHA-256(password123)
        
        User user = new User();
        user.setUsername("john");
        user.setPasswordHash(legacySHA256);
        userRepository.save(user);
        
        // 2. 사용자가 로그인
        String rawPassword = "password123";
        
        // ✅ DelegatingPasswordEncoder가 자동으로 SHA-256 검증
        boolean isValid = passwordEncoder.matches(rawPassword, legacySHA256);
        assertTrue(isValid);
        
        // 3. 검증 성공 후 업그레이드
        if (isValid && !legacySHA256.startsWith("{bcrypt}")) {
            String newBcryptHash = passwordEncoder.encode(rawPassword);
            user.setPasswordHash(newBcryptHash);
            userRepository.save(user);
            
            System.out.println("비밀번호 업그레이드 완료");
        }
        
        // 4. 다음 로그인부터는 Bcrypt 사용
        User updatedUser = userRepository.findByUsername("john").orElse(null);
        assertTrue(updatedUser.getPasswordHash().startsWith("{bcrypt}"));
    }
}
```

## 📊 공격 성공 조건 vs 방어 성공 조건 비교

| 항목 | 공격 성공 조건 | 방어 성공 조건 |
|------|--------------|--------------|
| **알고리즘** | MD5/SHA-1 | Bcrypt/Argon2 |
| **솔트** | 없음 | 자동 생성 + 포함 |
| **반복** | 1~10회 | 4096~262,144회 |
| **메모리** | 거의 없음 | 64MB (Argon2) |
| **Rainbow Table** | 사전 구축 가능 | 불가능 |
| **GPU 크래킹** | 밀리초 | 분~시간 |
| **Argon2 vs GPU** | 초당 수십억 | 초당 수십만 |

## ⚖️ 트레이드오프 (보안 강화 vs 사용성/성능)

### 1. Bcrypt Cost vs 로그인 속도
- **보안**: Cost 14 (약 1초 소요)
- **성능**: 사용자가 로그인 시 1초 대기
- **트레이드오프**: Cost 12~13 (약 200~500ms)

### 2. Argon2 메모리 vs 서버 리소스
- **보안**: 메모리 128MB (최강 보안)
- **성능**: 서버 메모리 부담 증가
- **트레이드오프**: 메모리 64MB (적정 수준)

### 3. 업그레이드 전략 vs 일괄 처리
- **보안**: 점진적 업그레이드 (사용자 로그인 시)
- **관리**: 구현 복잡도 증가
- **트레이드오프**: 로그인 시 자동 업그레이드 + 배치 작업

### 4. 타이밍 공격 방지 vs 성능
- **보안**: 항상 일정한 시간
- **성능**: 실패 케이스도 시간 소요
- **트레이드오프**: 무시할 수 있는 수준의 성능 저하

## 📌 핵심 정리

1. **Bcrypt 사용 (최소 Cost 12)**
   ```java
   new BCryptPasswordEncoder(12)
   ```

2. **자동 솔트 포함**
   ```java
   // Bcrypt가 자동으로 처리
   // 22자 솔트 + 해시
   ```

3. **DelegatingPasswordEncoder로 업그레이드**
   ```java
   DelegatingPasswordEncoder(idForEncode, encoders)
   ```

4. **로그인 시 자동 업그레이드**
   ```java
   if (passwordEncoder.matches(...) && needsUpgrade(...)) {
       user.setPasswordHash(passwordEncoder.encode(...));
   }
   ```

5. **타이밍 안전 비교**
   ```java
   passwordEncoder.matches(rawPassword, storedHash)
   ```

## 🤔 생각해볼 문제 (+ 해설)

### 문제 1: Bcrypt가 있는데 왜 Argon2도 필요한가?
**해설:**
- Bcrypt는 2004년 설계 (20년 전)
- GPU 성능이 대폭 향상됨
- Argon2는 2015년 설계 (GPU/병렬화 저항 고려)
- 차이:
  - Bcrypt: Cost 12에서 초당 약 100만 해시
  - Argon2: 초당 약 100만 해시도 불가능 (메모리 제약)
- **권장**: 새 프로젝트는 Argon2, 기존 프로젝트는 Bcrypt

### 문제 2: Cost를 50으로 설정하면 더 안전한가?
**해설:**
- 이론적으로 맞음 (2^50 = 1,125,899,906,842,624 iterations)
- 실제 문제:
  - 로그인 시간: 몇 시간 (실용적이지 않음)
  - 서버 과부하
- **따라서 Cost는 12~14 권장**
- 추가 보안이 필요하면 Argon2로 업그레이드

### 문제 3: 해시 함수로 SHA-256을 반복해도 되는가?
**해설:**
- 기술적으로 가능하지만 (PBKDF2가 그렇게 함)
- 문제:
  - 구현이 복잡 (코스 계수 설정)
  - Bcrypt가 이미 최적화됨
  - 보안 감사 부족
- **따라서 Bcrypt/Argon2 권장**

### 문제 4: 레거시 시스템에서 SHA-1로 저장된 비밀번호를 어떻게 마이그레이션하는가?
**해설:**
- **방법 1: 로그인 시 업그레이드**
  ```
  1. 사용자 로그인
  2. SHA-1으로 검증 (DelegatingPasswordEncoder)
  3. 성공 시 Bcrypt로 재해시
  4. 점진적 마이그레이션
  ```

- **방법 2: 비밀번호 리셋 강요**
  ```
  1. 모든 사용자에게 비밀번호 변경 요청
  2. 새 비밀번호는 Bcrypt로 저장
  3. 강제성 있음
  ```

- **방법 3: 하이브리드**
  ```
  1. 처음 1개월: 로그인 시 자동 업그레이드
  2. 2개월째: 업그레이드 권장 이메일
  3. 3개월째: 비밀번호 리셋 강제
  ```

---

<div align="center">

**[⬅️ 이전: 브루트포스와 계정 보호](./06-bruteforce-account-protection.md)** | **[홈으로 🏠](../README.md)** | **[다음: Chapter 4 — XSS 3가지 유형 ➡️](../web-vulnerabilities/01-xss-types.md)**

</div>
