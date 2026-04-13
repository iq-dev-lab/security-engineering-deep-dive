# 암호화 설계

---

## 🎯 핵심 질문

- **대칭 암호화(AES)와 비대칭 암호화(RSA)를 어떻게 구분하는가?** 대칭키는 공유 가능하고 빠르지만 키 배포가 어렵고, 비대칭키는 키 배포가 쉽지만 느립니다.
- **AES-ECB는 왜 Penguin 패턴을 노출하는가?** 같은 평문 블록이 같은 암문으로 변환되어 시각적 패턴이 드러납니다.
- **AES-GCM의 IV(Nonce)를 재사용하면 안 되는 이유는?** 같은 IV로 암호화된 두 메시지의 XOR 결과에서 평문을 복원할 수 있습니다.
- **키 관리를 클라우드 KMS에 위탁하면 정말 안전한가?** 네, 하지만 호출 권한(IAM), 감사 로그(CloudTrail) 보안도 함께 관리해야 합니다.

---

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

### ECB 패턴 노출 (Microsoft Teams 비디오 암호화)
**배경**: 초기 Teams 암호화에서 AES-ECB가 사용되었을 때 발생.

**문제점**:
```
같은 평문 픽셀 블록 → 같은 암문 블록 → 이미지 패턴 유지
결과: 개인 영상에서 얼굴, 문서, 화면 등의 윤곽이 드러남
```

**Penguin 이미지 예시**:
- ECB 암호화: 펭귄의 검은색 부분이 유사한 암문으로 변환 → 펭귄 실루엣 명확
- CBC/CTR 암호화: 같은 픽셀도 랜덤 IV로 다르게 암호화 → 노이즈처럼 보임

### GnuTLS IV 재사용 버그 (CVE-2009-2409)
**배경**: GnuTLS 라이브러리가 AES-GCM 암호화 시 IV를 제대로 랜덤화하지 않음.

**공격**:
```
1. 같은 키(K)로 여러 메시지 암호화
2. IV가 재사용되면:
   C1 = E(K, M1, IV) = M1 ⊕ Keystream
   C2 = E(K, M2, IV) = M2 ⊕ Keystream (같은 Keystream!)
3. C1 ⊕ C2 = M1 ⊕ M2 (키스트림 소거)
4. M1을 알면 M2 복원 가능
```

**결과**: 수천 개의 암호화된 메시지에서 평문 정보 유출

---

## 😱 취약한 코드/설정 (Before — 원리를 모를 때의 구현)

### 취약 1: AES-ECB 사용 (Penguin 패턴 노출)

```java
@Service
public class InsecureEncryptionService {

    private final SecretKey secretKey;
    private final Cipher cipher;

    public InsecureEncryptionService(String base64Key) throws Exception {
        byte[] decodedKey = Base64.getDecoder().decode(base64Key);
        this.secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        
        // ❌ 위험: ECB 모드 사용 (IV 없음)
        this.cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    }

    // ❌ 위험: IV 없이 암호화
    public String encryptEcb(String plaintext) throws Exception {
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // 같은 평문은 같은 암문으로 변환됨 (패턴 드러남)
    public void demonstrateEcbWeakness() throws Exception {
        String block1 = "AAAAAAAAAAAAAAAA";  // 16바이트
        String block2 = "AAAAAAAAAAAAAAAA";  // 같은 16바이트
        
        String enc1 = encryptEcb(block1);
        String enc2 = encryptEcb(block2);
        
        System.out.println(enc1);  // 예: "abc123..."
        System.out.println(enc2);  // 예: "abc123..." (같음!)
    }
}
```

### 취약 2: IV 재사용 (GCM 모드)

```java
@Service
public class InsecureGcmService {

    private final SecretKey secretKey;
    private static final byte[] FIXED_IV = new byte[12];  // ❌ 위험: 고정된 IV

    public InsecureGcmService(String base64Key) throws Exception {
        byte[] decodedKey = Base64.getDecoder().decode(base64Key);
        this.secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    // ❌ 위험: 항상 같은 IV 사용
    public String encryptGcm(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        // FIXED_IV를 매번 사용 (같은 키 + 같은 IV = 재사용!)
        GCMParameterSpec spec = new GCMParameterSpec(128, FIXED_IV);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        
        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // 공격 예시:
    public void demonstrateIvReuseVulnerability() throws Exception {
        String message1 = "SECRET_PASSWORD_123";
        String message2 = "SECRET_PASSWORD_456";
        
        String ciphertext1 = encryptGcm(message1);
        String ciphertext2 = encryptGcm(message2);
        
        // 같은 키 + 같은 IV로 두 메시지 암호화
        // ciphertext1 XOR ciphertext2 = plaintext1 XOR plaintext2
        // plaintext1을 알면 plaintext2 복원 가능!
    }
}
```

### 취약 3: 하드코딩된 암호화 키

```java
@Service
public class InsecureKeyManagementService {

    // ❌ 위험: 소스 코드에 하드코딩된 키
    private static final String ENCRYPTION_KEY = "my-super-secret-key-12345678901234567890";

    // ❌ 위험: Base64로 "인코딩"된 키 (이것은 암호화가 아님!)
    private static final String ENCODED_KEY = Base64.getEncoder()
        .encodeToString("my-super-secret-key-12345678901234567890".getBytes());

    public String encryptWithHardcodedKey(String plaintext) throws Exception {
        // Git 리포지토리에 노출되는 키
        // 컴파일된 JAR에 포함되는 키
        // 역 엔지니어링으로 쉽게 추출 가능
        
        SecretKey key = new SecretKeySpec(
            ENCRYPTION_KEY.getBytes(), 0, 32, "AES");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        
        return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext.getBytes()));
    }
}
```

### 취약 4: IV 암호화에 미포함 (재사용 노출)

```java
@Service
public class InsecureIvHandlingService {

    private final SecretKey secretKey;

    public InsecureIvHandlingService(String base64Key) throws Exception {
        byte[] decodedKey = Base64.getDecoder().decode(base64Key);
        this.secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    // ❌ 위험: IV를 암호화 결과에 포함하지 않음
    public String encryptWithoutIvPrepended(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        
        byte[] encrypted = cipher.doFinal(plaintext.getBytes());
        
        // ❌ IV를 따로 저장/전송해야 하는데 관리가 어려움
        // 복호화 시 IV를 어떻게 복원할 것인가?
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // ❌ 위험: IV를 별도로 전송하면 동기화 문제 발생
    public String decryptWithoutIvPrepended(String ciphertext, String ivString) throws Exception {
        // IV 문자열을 잘못 받으면?
        // IV가 변조되면 복호화 실패
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(Base64.getDecoder().decode(ivString));
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        
        return new String(cipher.doFinal(Base64.getDecoder().decode(ciphertext)));
    }
}
```

---

## ✨ 방어 코드/설정 (After — 공격 원리를 알고 설계한 구현)

### 방어 1: AES-GCM + 랜덤 IV (안전한 대칭 암호화)

```java
@Service
public class SecureAesGcmService {

    private final SecretKey secretKey;
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;  // 96비트 (GCM 권장)
    private static final int GCM_TAG_LENGTH = 128;  // 128비트 인증 태그
    private static final int AES_KEY_SIZE = 256;  // 256비트 키

    @Autowired
    private KeyVaultService keyVaultService;  // KMS에서 키 조회

    public SecureAesGcmService(String keyVaultId) throws Exception {
        // ✅ 방어: 키를 KMS에서 조회 (키 서버에 저장)
        this.secretKey = keyVaultService.getKey(keyVaultId);
    }

    // ✅ 방어: 매번 새로운 랜덤 IV 생성
    public EncryptedData encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        
        // 1. 매번 새로운 IV 생성
        SecureRandom secureRandom = SecureRandom.getInstanceStrong();
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);
        
        // 2. GCM 파라미터 설정
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
        
        // 3. 암호화 수행
        byte[] encryptedData = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        
        // 4. IV + 암호문을 함께 반환 (IV는 재사용되지 않으므로 평문 전송 가능)
        return EncryptedData.builder()
            .iv(Base64.getEncoder().encodeToString(iv))
            .ciphertext(Base64.getEncoder().encodeToString(encryptedData))
            .build();
    }

    // ✅ 방어: IV를 암호화 결과에서 추출 후 복호화
    public String decrypt(EncryptedData encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        
        byte[] iv = Base64.getDecoder().decode(encryptedData.getIv());
        byte[] ciphertext = Base64.getDecoder().decode(encryptedData.getCiphertext());
        
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
        
        return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
    }

    @Data
    @Builder
    public static class EncryptedData {
        private String iv;
        private String ciphertext;
    }
}
```

### 방어 2: 하이브리드 암호화 (RSA + AES)

```java
@Service
public class HybridEncryptionService {

    @Autowired
    private SecureAesGcmService aesGcmService;

    private final PublicKey publicKey;
    private final PrivateKey privateKey;
    private static final String RSA_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final int RSA_KEY_SIZE = 4096;

    public HybridEncryptionService(String publicKeyPath, String privateKeyPath) throws Exception {
        this.publicKey = loadPublicKey(publicKeyPath);
        this.privateKey = loadPrivateKey(privateKeyPath);
    }

    // ✅ 방어: 하이브리드 암호화 (RSA는 작은 데이터만, AES는 대용량)
    public HybridEncryptedData encryptHybrid(String plaintext) throws Exception {
        // 1단계: 임의의 대칭키 생성 (AES-GCM용)
        SecretKey sessionKey = generateSessionKey();
        
        // 2단계: 평문을 대칭키로 암호화 (빠름)
        SecureAesGcmService.EncryptedData encryptedContent = 
            aesGcmService.encrypt(plaintext);
        
        // 3단계: 임의 대칭키를 공개키로 암호화 (RSA - 느림)
        Cipher rsaCipher = Cipher.getInstance(RSA_ALGORITHM);
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        
        byte[] encryptedSessionKey = rsaCipher.doFinal(
            sessionKey.getEncoded());
        
        // 4단계: 암호화된 세션키 + 암호화된 내용 전송
        return HybridEncryptedData.builder()
            .encryptedSessionKey(Base64.getEncoder().encodeToString(encryptedSessionKey))
            .encryptedContent(encryptedContent)
            .build();
    }

    // ✅ 방어: 하이브리드 복호화
    public String decryptHybrid(HybridEncryptedData hybridData) throws Exception {
        // 1단계: 암호화된 세션키를 개인키로 복호화
        Cipher rsaCipher = Cipher.getInstance(RSA_ALGORITHM);
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        
        byte[] decryptedSessionKeyBytes = rsaCipher.doFinal(
            Base64.getDecoder().decode(hybridData.getEncryptedSessionKey()));
        
        SecretKey sessionKey = new SecretKeySpec(
            decryptedSessionKeyBytes, 0, decryptedSessionKeyBytes.length, "AES");
        
        // 2단계: 복호화된 세션키로 내용 복호화
        return aesGcmService.decrypt(hybridData.getEncryptedContent());
    }

    private SecretKey generateSessionKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256, SecureRandom.getInstanceStrong());
        return keyGen.generateKey();
    }

    private PublicKey loadPublicKey(String path) throws Exception {
        // X.509 형식의 공개키 로드
        FileInputStream fis = new FileInputStream(path);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
        return cert.getPublicKey();
    }

    private PrivateKey loadPrivateKey(String path) throws Exception {
        // PKCS8 형식의 개인키 로드
        byte[] privateKeyBytes = Files.readAllBytes(Paths.get(path));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    @Data
    @Builder
    public static class HybridEncryptedData {
        private String encryptedSessionKey;
        private SecureAesGcmService.EncryptedData encryptedContent;
    }
}
```

### 방어 3: AWS KMS를 통한 키 관리

```java
@Service
public class KmsEncryptionService {

    @Autowired
    private KmsClient kmsClient;  // AWS KMS 클라이언트

    private static final String KEY_ALIAS = "alias/app-encryption-key";

    // ✅ 방어: AWS KMS에서 데이터 암호화 키 생성
    public EncryptedDataKey generateDataKey() {
        GenerateDataKeyRequest request = GenerateDataKeyRequest.builder()
            .keyId(KEY_ALIAS)
            .keySpec(DataKeySpec.AES_256)  // 256비트 데이터 암호화 키
            .build();

        GenerateDataKeyResponse response = kmsClient.generateDataKey(request);
        
        return EncryptedDataKey.builder()
            .plaintext(Base64.getEncoder().encodeToString(
                response.plaintext().asByteArray()))
            .encryptedKey(Base64.getEncoder().encodeToString(
                response.encryptedDataKey().asByteArray()))
            .build();
    }

    // ✅ 방어: 암호화된 데이터 키 복호화
    public String decryptDataKey(String encryptedKey) {
        DecryptRequest request = DecryptRequest.builder()
            .ciphertextBlob(SdkBytes.fromByteArray(
                Base64.getDecoder().decode(encryptedKey)))
            .build();

        DecryptResponse response = kmsClient.decrypt(request);
        
        return Base64.getEncoder().encodeToString(
            response.plaintext().asByteArray());
    }

    // ✅ 방어: KMS를 통한 데이터 암호화 (자동 키 로테이션)
    public String encryptWithKms(String plaintext) {
        EncryptRequest request = EncryptRequest.builder()
            .keyId(KEY_ALIAS)
            .plaintext(SdkBytes.fromByteArray(plaintext.getBytes(StandardCharsets.UTF_8)))
            .build();

        EncryptResponse response = kmsClient.encrypt(request);
        
        return Base64.getEncoder().encodeToString(
            response.ciphertextBlob().asByteArray());
    }

    @Data
    @Builder
    public static class EncryptedDataKey {
        private String plaintext;
        private String encryptedKey;
    }
}
```

**AWS KMS 설정** (CloudFormation):
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  AppEncryptionKey:
    Type: AWS::KMS::Key
    Properties:
      Description: "Application data encryption key"
      KeyPolicy:
        Version: '2012-10-17'
        Statement:
          - Sid: Enable IAM policies
            Effect: Allow
            Principal:
              AWS: !Sub 'arn:aws:iam::${AWS::AccountId}:root'
            Action: 'kms:*'
            Resource: '*'
          - Sid: Allow EC2 to use key
            Effect: Allow
            Principal:
              Service: ec2.amazonaws.com
            Action:
              - 'kms:Decrypt'
              - 'kms:GenerateDataKey'
            Resource: '*'

  AppEncryptionKeyAlias:
    Type: AWS::KMS::Alias
    Properties:
      AliasName: alias/app-encryption-key
      TargetKeyId: !Ref AppEncryptionKey

  # CloudTrail로 KMS 접근 로깅 (감사)
  KmsAuditTrail:
    Type: AWS::CloudTrail::Trail
    Properties:
      S3BucketName: !Ref AuditBucket
      IsLogging: true
      IncludeGlobalServiceEvents: true
      TrailName: kms-audit
      EventSelectors:
        - IncludeManagementEvents: true
          ReadWriteType: All
```

### 방어 4: Spring JPA AttributeConverter로 컬럼 암호화

```java
// ✅ 방어: JPA가 자동으로 컬럼 암호화/복호화
@Converter(autoApply = true)
public class EncryptedAttributeConverter implements AttributeConverter<String, String> {

    @Autowired
    private SecureAesGcmService aesGcmService;

    @Override
    public String convertToDatabaseColumn(String attribute) {
        if (attribute == null) return null;
        
        try {
            SecureAesGcmService.EncryptedData encrypted = 
                aesGcmService.encrypt(attribute);
            // JSON으로 저장: {"iv":"...", "ciphertext":"..."}
            return new JSONObject()
                .put("iv", encrypted.getIv())
                .put("ciphertext", encrypted.getCiphertext())
                .toString();
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    @Override
    public String convertToEntityAttribute(String dbData) {
        if (dbData == null) return null;
        
        try {
            JSONObject json = new JSONObject(dbData);
            SecureAesGcmService.EncryptedData encrypted = 
                SecureAesGcmService.EncryptedData.builder()
                    .iv(json.getString("iv"))
                    .ciphertext(json.getString("ciphertext"))
                    .build();
            
            return aesGcmService.decrypt(encrypted);
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }
}

// 사용 예시
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;

    // ✅ 자동으로 암호화/복호화됨
    @Convert(converter = EncryptedAttributeConverter.class)
    @Column(name = "encrypted_ssn")
    private String ssn;

    @Convert(converter = EncryptedAttributeConverter.class)
    @Column(name = "encrypted_credit_card")
    private String creditCard;
}

// 사용 (개발자는 평문으로 작업)
User user = new User();
user.setUsername("john");
user.setSsn("123-45-6789");  // 자동 암호화
userRepository.save(user);

User retrieved = userRepository.findById(1L);
String decryptedSsn = retrieved.getSsn();  // 자동 복호화 → "123-45-6789"
```

---

## 🔬 공격 원리 분석 (공격자 관점의 내부 동작)

### ECB 모드 Penguin 이미지 복원

```
원본 이미지 (평문):
████████████████
████████████████
█████░░░░░░░░██
█████░░░░░░░░██
████████████████

ECB 암호화 (같은 픽셀 = 같은 암호):
████████████████  → AAAA...AAAA
████████████████  → AAAA...AAAA (반복!)
█████░░░░░░░░██  → BBBB...CCCC
█████░░░░░░░░██  → BBBB...CCCC (반복!)
████████████████  → AAAA...AAAA

패턴이 드러남 → 펭귄 실루엣 복원!

CBC/CTR 암호화 (IV로 랜덤화):
████████████████  → RAND1...
████████████████  → RAND2... (다름!)
█████░░░░░░░░██  → RAND3...
█████░░░░░░░░██  → RAND4... (다름!)
████████████████  → RAND5...

패턴 없음 → 노이즈 같음 (안전)
```

### GCM IV 재사용 공격

```
상황: 같은 키 K, 같은 IV로 두 메시지 암호화

Message 1: "SECRET_PASSWORD_1"
Message 2: "SECRET_PASSWORD_2"

GCM은 다음과 같이 작동:
C1 = M1 ⊕ Keystream(K, IV)
C2 = M2 ⊕ Keystream(K, IV)

C1 ⊕ C2 = (M1 ⊕ Keystream) ⊕ (M2 ⊕ Keystream)
        = M1 ⊕ M2

공격자가 M1을 알면:
M2 = (C1 ⊕ C2) ⊕ M1

또는 알려진 평문 공격:
"SECRET_PASSWORD_1" ⊕ C1 = Keystream
Keystream ⊕ C2 = M2
```

---

## 💻 실전 실험 (취약점 재현 → 공격 → 방어 검증)

### 실험 1: ECB vs CBC 시각적 비교

```java
public class EcbVsCbcDemo {

    public static void main(String[] args) throws Exception {
        // 1. 펭귄 이미지를 2D 배열로 로드
        BufferedImage penguin = ImageIO.read(new File("penguin.png"));
        int[][] pixels = extractPixels(penguin);

        // 2. ECB 암호화
        int[][] ecbEncrypted = encryptEcb(pixels);
        BufferedImage ecbImage = createImage(ecbEncrypted);
        ImageIO.write(ecbImage, "png", new File("penguin-ecb.png"));
        // 결과: 펭귄 실루엣이 명확히 드러남

        // 3. CBC 암호화
        int[][] cbcEncrypted = encryptCbc(pixels);
        BufferedImage cbcImage = createImage(cbcEncrypted);
        ImageIO.write(cbcImage, "png", new File("penguin-cbc.png"));
        // 결과: 무작위 노이즈처럼 보임
    }

    private static int[][] encryptEcb(int[][] pixels) throws Exception {
        SecretKey key = generateKey();
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        // 각 16바이트 블록을 개별 암호화
        // 같은 픽셀 블록 = 같은 암호문
        // ...
        return pixels;  // 간소화됨
    }

    private static int[][] encryptCbc(int[][] pixels) throws Exception {
        SecretKey key = generateKey();
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        
        byte[] iv = new byte[16];
        SecureRandom.getInstanceStrong().nextBytes(iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        // 이전 암호문 블록이 다음 평문 블록과 XOR됨
        // → 같은 평문 ≠ 같은 암호문
        // ...
        return pixels;
    }
}
```

### 실험 2: IV 재사용 공격 시연

```bash
# 1. 같은 키, 같은 IV로 두 메시지 암호화
PLAINTEXT1="This is message one"
PLAINTEXT2="This is message two"

java IvReuseDemo encrypt "$PLAINTEXT1" > ct1.bin
java IvReuseDemo encrypt "$PLAINTEXT2" > ct2.bin

# 2. 암호문 XOR (같은 Keystream 소거)
java -cp . XorFiles ct1.bin ct2.bin > m1_xor_m2.bin

# 3. M1을 알면 M2 복원
java DecryptViaXor m1_xor_m2.bin "$PLAINTEXT1"
# 출력: "This is message two" (원본을 모르는데도 복원!)
```

### 실험 3: AWS KMS 통합 테스트

```java
@SpringBootTest
class KmsEncryptionServiceTest {

    @Autowired
    private KmsEncryptionService kmsService;

    @Test
    void testKmsDataEncryption() {
        // 1. KMS에서 데이터 암호화 키 생성
        KmsEncryptionService.EncryptedDataKey dataKey = 
            kmsService.generateDataKey();
        
        // 2. 데이터 키로 민감 데이터 암호화
        String sensitiveData = "credit-card-4532-1234-5678-9012";
        byte[] encrypted = encryptWithAes(sensitiveData, 
            Base64.getDecoder().decode(dataKey.getPlaintext()));
        
        // 3. 암호화된 데이터 키 + 암호화된 데이터를 함께 저장
        storeInDatabase(dataKey.getEncryptedKey(), encrypted);
        
        // 4. 나중에 복호화할 때 KMS에서 데이터 키 복호화
        String decryptedKey = kmsService.decryptDataKey(
            dataKey.getEncryptedKey());
        
        // 5. 복호화된 데이터 키로 민감 데이터 복호화
        String decrypted = decryptWithAes(encrypted,
            Base64.getDecoder().decode(decryptedKey));
        
        assertEquals(sensitiveData, decrypted);
    }

    @Test
    void testKmsKeyRotation() throws InterruptedException {
        // AWS KMS는 자동으로 키를 로테이션
        // CloudTrail에서 로테이션 이벤트 확인
        Thread.sleep(86400000);  // 1일 대기 (실제 테스트는 모의)
        
        // 로테이션 후에도 이전 데이터 복호화 가능
        // (KMS가 키 버전 관리)
    }
}
```

---

## 📊 공격 성공 조건 vs 방어 성공 조건 비교

| 조건 | 공격 성공 | 방어 성공 |
|------|---------|---------|
| **모드** | ECB 또는 CBC with 고정 IV | GCM with 랜덤 IV |
| **IV** | 재사용되거나 고정됨 | 매번 새로운 랜덤 IV |
| **키** | 소스 코드에 하드코딩 | KMS에서 관리 |
| **키 저장** | 평문 저장 | 암호화 저장 |
| **패턴** | ECB에서 반복 패턴 발생 | 패턴 없음 |
| **인증** | 인증 태그 없음 (무결성 미검증) | GCM으로 인증 태그 포함 |

---

## ⚖️ 트레이드오프 (보안 강화 vs 사용성/성능)

| 방어 기법 | 보안 수준 | 성능 영향 | 구현 복잡도 |
|---------|----------|---------|----------|
| **AES-GCM** | ⭐⭐⭐⭐⭐ | 중간 | 중간 |
| **하이브리드(RSA+AES)** | ⭐⭐⭐⭐⭐ | 높음 (RSA 느림) | 높음 |
| **AWS KMS** | ⭐⭐⭐⭐⭐ | 높음 (네트워크) | 중간 |
| **JPA AttributeConverter** | ⭐⭐⭐⭐ | 중간 | 낮음 |
| **시스템 메모리 암호화** | ⭐⭐⭐ | 높음 | 높음 |

---

## 📌 핵심 정리

1. **ECB는 절대 금지**: 반복되는 평문이 같은 암문으로 변환되어 패턴 노출
2. **IV는 매번 랜덤**: 같은 키로 암호화해도 IV가 다르면 같은 암문 불가능
3. **IV 재사용 = 치명적**: GCM 모드에서는 Keystream 소거로 평문 복원 가능
4. **대칭 vs 비대칭**: 대용량 데이터는 AES(대칭), 키 교환은 RSA(비대칭)
5. **키 관리는 AWS KMS**: 소스 코드에 키 저장 금지, KMS 위탁
6. **하이브리드 암호화**: 실제 데이터는 AES, 세션키는 RSA로 보호
7. **JPA AttributeConverter**: Spring 개발자가 자동 암호화 구현 가능

---

## 🤔 생각해볼 문제 (+ 해설)

### Q1. GCM의 IV(Nonce)는 정말 "non-reusable"인가?
**해설**: 네, GCM은 특별히 IV 재사용을 엄격히 금지합니다. 같은 키로 같은 IV 두 번 사용 시 공격자가 평문을 복원할 수 있습니다 (IV 재사용 취약점). 따라서 IV를 충분히 큰 범위(96비트)에서 세밀한 엔트로피로 생성해야 합니다.

### Q2. AWS KMS가 해킹되면 어떻게 되는가?
**해설**: KMS 자체는 AWS에서 HSM(Hardware Security Module)으로 보호됩니다. 그보다 중요한 것은 IAM 접근 권한 관리와 CloudTrail 감사 로그입니다. 만약 권한 없는 사용자가 KMS 키 접근을 시도하면 즉시 감지할 수 있습니다.

### Q3. 하이브리드 암호화에서 세션키 크기는?
**해설**: 세션키는 대칭 알고리즘(AES-256)에 맞춰 32바이트(256비트) 생성합니다. 이 세션키를 RSA-4096으로 암호화하면 안전합니다. 만약 세션키 자체가 약하면 대칭 암호화의 강점이 무용지물입니다.

### Q4. IV를 암호화 결과 앞에 붙여도 되는가?
**해설**: 네, 안전합니다. IV는 평문이 아니므로 암호화할 필요가 없습니다. 암호문 앞에 IV를 붙이는 방식이 가장 간단합니다. 단, IV가 변조되면 복호화가 실패하지만 평문이 노출되지는 않습니다.

<div align="center">

**[⬅️ 이전: 민감 데이터 노출](./02-sensitive-data-exposure.md)** | **[홈으로 🏠](../README.md)** | **[다음: 보안 설정 오류 ➡️](./04-security-misconfiguration.md)**

</div>
