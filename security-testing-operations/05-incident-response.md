# 인시던트 대응

---

## 🎯 핵심 질문

- **보안 사건 대응의 4단계는?** Containment (격리) → Investigation (조사) → Recovery (복구) → Post-Mortem (사후 분석)
- **개인정보보호법상 사용자 통지 의무는?** 침해 발생 72시간 이내에 영향받은 개인에게 알려야 합니다.
- **포렌식 로그를 보존하는 방법은?** WORM(Write Once Read Many) 스토리지 또는 불변 S3 버킷 사용합니다.
- **체인 오브 커스터디(Chain of Custody)란?** 증거의 출처, 보관, 이동 기록을 철저히 남기는 것입니다.

---

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

### Uber 침해 사건 (2022) — 대응 실패
**배경**: Uber가 클라우드 자격증명이 유출된 후 해커와 협상하려 했으나, 결국 13년 치 사용자 데이터 노출.

**문제점**:
```
1. 초기 감지: 관리자가 git 리포지토리에 AWS 키 발견
   → 5시간 동안 대응 없음

2. 초기 대응 실패: 키를 비활성화하지 않음
   → 해커가 계속 접근

3. 포렌식 미흡: 어느 데이터가 유출됐는지 파악 불가능
   → 규제 기관에 불명확한 정보 제공

4. 사용자 공지 늦음: 발견 후 몇 주 뒤에 공지
   → 개인정보보호법 위반 (72시간 규정)

5. 결과:
   - $148 million 합의금
   - CEO 교체
   - 신뢰도 상실
```

---

## 😱 취약한 대응 (Before — 체계적 대응 미흡)

### 취약 1: 대응 계획 부재

```yaml
# ❌ 위험: 인시던트 대응 계획(IRP) 전혀 없음

# 현상:
# 1. 보안 팀이 침해 의심 신고
#    → 누구에게? (담당자 불명확)
#    → 언제? (긴급도 판단 안 함)

# 2. 경영진은 모름
#    → 미디어가 먼저 보도
#    → 신뢰도 급락

# 3. 기술 팀은 대응 지시 못 받음
#    → 로그 덮어씀
#    → 포렌식 증거 소실

# 4. 법무 팀은 규제 기관 요구에 대응 못 함
#    → 72시간 공지 기한 놓침
#    → 규제 벌금
```

### 취약 2: 로그 보존 미흡

```java
// ❌ 위험: 로그 자동 삭제 설정
@Configuration
public class InsecureLoggingConfig {

    @Bean
    public RollingFileAppender loggingAppender() {
        RollingFileAppender appender = new RollingFileAppender();
        
        // 7일마다 자동 삭제
        appender.setMaxHistory(7);  // ❌ 침해 사고 조사에 필요한 로그 소실
        
        return appender;
    }
}

// 결과:
// 1. 침해 발생: 2024-01-15
// 2. 발견: 2024-01-18 (3일 후)
// 3. 로그 확인 시도: 2024-01-18
// → 7일 이전 로그(2024-01-11 이전)는 이미 삭제됨
// → 침해 경로 추적 불가능
```

### 취약 3: 포렌식 증거 체인 없음

```bash
# ❌ 위험: 증거 보관 기록 없음

# 상황:
# 1. 수사팀이 서버 로그 요청
# 2. IT팀: "여기 있습니다" (파일 전달)
# 3. 검사: "이 파일이 정말 원본인가?"
#    - 누가 어디에서 추출했는가?
#    - 언제 추출했는가?
#    - 중간에 수정되지 않았는가?
# 4. IT팀: "몰라요" (증거 체인 기록 없음)
# 5. 법원: "증거 가치 없음" (인정 불가)

# 결과:
# → 침해자 처벌 불가능
# → 민사 소송에서 배상액 감소
```

---

## ✨ 방어 코드/설정 (After — 체계적 인시던트 대응)

### 방어 1: 인시던트 대응 계획 (IRP)

```markdown
# 인시던트 대응 계획 (IRP)

## 1. 역할 및 책임

### 보안 팀 (24시간 온콜)
- 침해 초기 대응
- 영향 범위 파악
- 복구 지시

### 경영진 (의사결정)
- 24시간 내 상황 보고 수락
- 규제 기관 공지 승인
- 미디어 대응 결정

### 법무 팀 (규제 준수)
- 개인정보보호법 통지 요구사항 확인
- 신용정보법 규정 확인
- 변호사 선임

### 기술 팀 (복구)
- 시스템 격리
- 로그 보존
- 복구 작업

### IR 팀 (조율)
- 일일 미팅 진행 (사건 발생 후)
- 진행 상황 추적
- 회의록 기록

## 2. 초기 대응 (0-2시간)

| 시간 | 담당 | 작업 |
|------|------|------|
| T+0 | 탐지자 | 침해 신고 (즉시 차장급 이상에 보고) |
| T+15분 | 보안팀 | 영향 범위 초기 판단 |
| T+30분 | 경영진 | 상황 보고 수청 |
| T+1시간 | 기술팀 | 감염 서버 네트워크 격리 |
| T+1시간 | 법무팀 | 외부 변호사 선임 |
| T+2시간 | IR팀 | 첫 회의 개최, 수습팀 구성 |

## 3. 중기 대응 (2-24시간)

| 시간 | 작업 | 담당 |
|------|------|------|
| T+2시간 | 포렌식 이미지 생성 | 기술팀 |
| T+4시간 | 규제 기관 통지 준비 | 법무팀 |
| T+12시간 | 완전한 영향 범위 파악 | 보안팀 |
| T+24시간 | 사용자 통지 완료 | 법무팀 + 마케팅팀 |

## 4. 사용자 공지 프로세스

1. **내용**: "2024-01-15에 침해 발생, 당신의 이메일과 이름이 유출"
2. **방법**: 이메일, SMS, 사이트 공지
3. **기간**: 침해 발견 72시간 이내
4. **무료 신용 모니터링**: 피해자에게 1년 무료 제공
5. **콜센터**: 피해자 질문 대응 (전담팀 구성)

## 5. 사후 분석 (발생 후 2주)

- 침해 원인 분석
- 방어 실패 지점
- 개선 계획 수립
- 경영진 결과 보고
```

### 방어 2: 로그 보존 및 포렌식

```yaml
# docker-compose.yml (로그 수집 시스템)
version: '3.8'

services:
  # ✅ 중앙 로그 저장소 (Elasticsearch)
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.0.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=true
      - xpack.security.enrollment.enabled=true
    ports:
      - "9200:9200"
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data
    networks:
      - logging

  # ✅ 로그 에이전트 (Filebeat)
  filebeat:
    image: docker.elastic.co/beats/filebeat:8.0.0
    user: root
    volumes:
      - /var/log:/var/log:ro
      - ./filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
      - /var/lib/docker/containers:/var/lib/docker/containers:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
    command: filebeat -e -strict.perms=false
    depends_on:
      - elasticsearch
    networks:
      - logging

  # ✅ 로그 시각화 (Kibana)
  kibana:
    image: docker.elastic.co/kibana/kibana:8.0.0
    ports:
      - "5601:5601"
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    depends_on:
      - elasticsearch
    networks:
      - logging

  # ✅ 불변 백업 (AWS S3)
  logstash:
    image: docker.elastic.co/logstash/logstash:8.0.0
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf:ro
    depends_on:
      - elasticsearch
    environment:
      - AWS_REGION=us-east-1
      - AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
      - AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
    networks:
      - logging

volumes:
  elasticsearch_data:

networks:
  logging:
    driver: bridge
```

**logstash.conf** (S3에 자동 백업):
```
input {
  elasticsearch {
    hosts => "elasticsearch:9200"
    index => "security-logs-*"
    query => '{ "query": { "match_all": {} } }'
    scroll => "5m"
    docinfo => true
  }
}

filter {
  # 필터링
}

output {
  # ✅ S3에 불변 저장
  s3 {
    region => "us-east-1"
    bucket => "security-logs-backup"
    key => "logs-%{+YYYY-MM-dd-HH-mm-ss}"
    codec => "json_lines"
    storage_class => "GLACIER"  # 저가 저장소
  }

  # ✅ 로컬 WORM 저장소 (Write Once Read Many)
  file {
    path => "/mnt/worm-storage/logs-%{+YYYY-MM-dd}.log"
    codec => "line"
  }
}
```

### 방어 3: 포렌식 증거 체인

```java
@Component
public class ForensicEvidenceService {

    // ✅ 증거 추출 시 기록
    public ForensicEvidence extractEvidence(String source, LocalDateTime period) {
        
        // 1. 증거 수집
        List<SecurityLog> logs = securityLogRepository.findByTimestampBetween(period);
        byte[] evidence = serializeToBytes(logs);
        
        // 2. 해시 생성 (무결성 검증)
        String sha256Hash = calculateSHA256(evidence);
        
        // 3. 증거 체인 기록
        ForensicEvidence forensicEvidence = new ForensicEvidence();
        forensicEvidence.setSourceSystem(source);
        forensicEvidence.setCollectionTime(LocalDateTime.now());
        forensicEvidence.setCollectedBy(getCurrentUser());
        forensicEvidence.setTimeRange(period);
        forensicEvidence.setHash(sha256Hash);  // 무결성 검증용
        forensicEvidence.setStorageLocation("/mnt/worm/evidence-" + UUID.randomUUID());
        
        // 4. 증명 체인 기록
        ChainOfCustody chain = new ChainOfCustody();
        chain.setEvidence(forensicEvidence);
        chain.setAction("COLLECTED");
        chain.setTimestamp(LocalDateTime.now());
        chain.setResponsiblePerson(getCurrentUser());
        chain.setSignature(signEvidence(forensicEvidence));
        
        chainOfCustodyRepository.save(chain);
        
        // 5. 장기 보관 (WORM 스토리지)
        storeInWormStorage(forensicEvidence);
        
        return forensicEvidence;
    }

    // ✅ 증거 접근 추적
    public void accessEvidence(ForensicEvidence evidence, String purpose) {
        ChainOfCustody accessRecord = new ChainOfCustody();
        accessRecord.setEvidence(evidence);
        accessRecord.setAction("ACCESSED");
        accessRecord.setPurpose(purpose);
        accessRecord.setTimestamp(LocalDateTime.now());
        accessRecord.setResponsiblePerson(getCurrentUser());
        accessRecord.setIpAddress(getClientIp());
        
        chainOfCustodyRepository.save(accessRecord);
    }

    // ✅ 증거 무결성 검증
    public boolean verifyEvidenceIntegrity(ForensicEvidence evidence) {
        byte[] evidenceData = loadFromStorage(evidence.getStorageLocation());
        String currentHash = calculateSHA256(evidenceData);
        
        return currentHash.equals(evidence.getHash());
    }

    // ✅ 증거 체인 완전성 검증
    public boolean verifyChainOfCustody(ForensicEvidence evidence) {
        List<ChainOfCustody> chain = chainOfCustodyRepository
            .findByEvidenceOrderByTimestamp(evidence);
        
        // 모든 단계에서 서명 검증
        for (ChainOfCustody record : chain) {
            if (!verifySignature(record)) {
                return false;  // 위변조 감지
            }
        }
        
        return true;
    }

    private String signEvidence(ForensicEvidence evidence) {
        String data = evidence.getHash() + evidence.getCollectionTime();
        String privateKey = getPrivateKey();  // 비밀 키 (HSM에 저장)
        
        return signWithRSA(data, privateKey);
    }

    private boolean verifySignature(ChainOfCustody record) {
        String publicKey = getPublicKey();
        return verifyRSASignature(record.getSignature(), record.getHash(), publicKey);
    }
}

@Data
@Entity
public class ForensicEvidence {
    @Id
    @GeneratedValue
    private Long id;
    
    private String sourceSystem;  // "elasticsearch", "postgres", etc.
    private LocalDateTime collectionTime;
    private String collectedBy;
    private String timeRange;  // "2024-01-15 14:00 - 16:00"
    private String hash;  // SHA-256
    private String storageLocation;  // WORM 스토리지 경로
}

@Data
@Entity
public class ChainOfCustody {
    @Id
    @GeneratedValue
    private Long id;
    
    @ManyToOne
    private ForensicEvidence evidence;
    
    private String action;  // "COLLECTED", "ACCESSED", "TRANSFERRED"
    private LocalDateTime timestamp;
    private String responsiblePerson;
    private String purpose;  // "ACCESS"인 경우 목적 기록
    private String ipAddress;
    private String signature;  // RSA 전자 서명
}
```

### 방어 4: 사용자 통지 자동화

```java
@Component
public class IncidentNotificationService {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private EmailService emailService;
    @Autowired
    private SmsService smsService;
    @Autowired
    private NotificationLogRepository logRepository;

    // ✅ 72시간 내 사용자 공지 (개인정보보호법)
    public void notifyAffectedUsers(IncidentReport incident) throws Exception {
        
        // 1. 영향받은 사용자 식별
        List<User> affectedUsers = identifyAffectedUsers(incident);
        
        // 2. 공지 내용 작성
        String emailContent = formatIncidentNotification(incident);
        String smsContent = formatSmsNotification(incident);
        
        // 3. 공지 시작 시간 기록
        incident.setNotificationStartTime(LocalDateTime.now());
        incidentRepository.save(incident);
        
        // 4. 사용자별 공지 (비동기)
        for (User user : affectedUsers) {
            notifyUser(user, incident, emailContent, smsContent);
        }
        
        // 5. 규제 기관 공시 (필요시)
        if (incident.getSeverity().equals("CRITICAL")) {
            notifyRegulatoryBodies(incident);
        }
    }

    private void notifyUser(User user, IncidentReport incident, 
                           String emailContent, String smsContent) {
        try {
            // 1. 이메일 발송
            emailService.sendSecure(user.getEmail(), 
                "보안 사건 공지 - 긴급", emailContent);
            
            // 2. SMS 발송 (중요도 높은 경우)
            if (incident.getSeverity().equals("CRITICAL")) {
                smsService.send(user.getPhone(), smsContent);
            }
            
            // 3. 개인 대시보드 알림
            dashboardService.notifyUser(user.getId(), 
                "귀하의 계정이 보안 사건의 영향을 받았습니다");
            
            // 4. 공지 기록
            NotificationLog log = new NotificationLog();
            log.setIncident(incident);
            log.setUser(user);
            log.setEmailSentAt(LocalDateTime.now());
            log.setEmailStatus("SUCCESS");
            logRepository.save(log);
            
        } catch (Exception e) {
            // 재시도 로직
            scheduleRetry(user, incident, 3);
        }
    }

    // ✅ 무료 신용 모니터링 제공
    private void offerCreditMonitoring(User user) {
        String monitoringCode = UUID.randomUUID().toString();
        
        user.setCreditMonitoringCode(monitoringCode);
        user.setCreditMonitoringExpiresAt(
            LocalDateTime.now().plusYears(1));
        userRepository.save(user);
        
        // 써드파티 신용 모니터링 업체에 등록
        creditMonitoringService.register(user, monitoringCode);
    }

    // ✅ 콜센터 지원
    public void setupIncidentCallCenter(IncidentReport incident) {
        CallCenter center = new CallCenter();
        center.setIncident(incident);
        center.setPhoneNumber("1-800-XXX-XXXX");  // 전용 번호
        center.setOperatingHours("24/7");
        center.setLanguages(Arrays.asList("EN", "KO", "ES", "FR"));
        center.setStaffingLevel(100);  // 100명 배치
        
        callCenterRepository.save(center);
    }
}

private String formatIncidentNotification(IncidentReport incident) {
    return String.format(
        "안녕하세요,\n\n" +
        "당사는 귀하의 개인정보 보호를 최우선으로 생각합니다.\n\n" +
        
        "발생 날짜: %s\n" +
        "발견 날짜: %s\n" +
        "영향받은 정보: %s\n\n" +
        
        "취해야 할 조치:\n" +
        "1. 비밀번호 변경\n" +
        "2. 신용카드 모니터링\n" +
        "3. 무료 신용 모니터링 등록: %s\n\n" +
        
        "문의: %s (24시간 운영)\n",
        
        incident.getIncidentDate(),
        incident.getDiscoveryDate(),
        incident.getAffectedDataTypes(),
        incident.getCreditMonitoringUrl(),
        incident.getIncidentHotline()
    );
}
```

### 방어 5: 사후 분석 (Post-Mortem)

```markdown
# 사후 분석 보고서 (Post-Mortem)

## 사건 개요

- **사건명**: 2024-01-15 고객 데이터 유출
- **발생 날짜**: 2024-01-15 14:30 UTC
- **발견 날짜**: 2024-01-18 08:15 UTC
- **영향 범위**: 1.2백만 명 (이메일, 이름)
- **심각도**: CRITICAL

## 침해 원인

### 근본 원인 분석 (RCA)

**직접 원인**:
1. AWS 접근 키가 GitHub 리포지토리에 실수로 커밋됨
2. 해커가 이 키를 사용하여 S3 버킷 접근
3. 네트워크 세그멘테이션 없어서 데이터베이스도 접근 가능

**기본 원인** (왜 발생했나?):
1. 비밀번호 관리 도구 미사용 (AWS Secrets Manager)
2. git-secrets 훅 미설치
3. 접근 키 로테이션 미실시 (3년간 같은 키)

## 개선 계획

| 항목 | 우선순위 | 담당팀 | 마감일 |
|------|---------|--------|--------|
| AWS Secrets Manager 도입 | P0 | DevOps | 2024-02-15 |
| git-secrets pre-commit 훅 | P0 | DevOps | 2024-02-01 |
| 월간 접근 키 로테이션 | P0 | Security | 2024-02-01 |
| VPC 네트워크 세그멘테이션 | P1 | DevOps | 2024-03-15 |
| 24/7 모니터링 체제 구축 | P1 | Security | 2024-03-01 |
| 정기 침투 테스트 | P2 | Security | 2024-06-01 |

## 교훈

1. **즉시 대응의 중요성**: 발견 후 5시간이 아니라 5분 내에 대응했어야 함
2. **로그 보관의 필수성**: 증거 체인 미흡으로 침해 범위 파악 어려움
3. **자동화의 필요성**: 사람 실수를 줄이기 위해 비밀번호 관리 자동화 필수
4. **거버넌스**: 접근 권한이 너무 많았음 (최소 권한 원칙 위반)
```

---

## 📌 핵심 정리

1. **IRP(Incident Response Plan) 필수**: 역할, 절차, 연락처를 사전에 정의
2. **초기 대응 72시간**: 격리, 조사, 사용자 공지 모두 신속히
3. **포렌식 증거 보관**: 해시, 서명, 체인 오브 커스터디로 무결성 보증
4. **중앙 집중 로그**: ELK Stack, CloudWatch로 침해 추적 용이
5. **사용자 공지**: 개인정보보호법 72시간 규정 준수
6. **사후 분석**: 근본 원인 파악 및 개선 계획 수립

---

## 🤔 생각해볼 문제 (+ 해설)

### Q1. 침해 사실을 공개하지 않고 내부에서만 처리할 수는 없을까?
**해설**: 불가능합니다. 개인정보보호법(GDPR, CCPA, 한국 PIPA)에서 72시간 내 공지 의무가 있습니다. 위반 시 최대 매출의 4%~20% 벌금.

### Q2. 포렌식 증거가 법정에서 인정되지 않으면?
**해설**: 체인 오브 커스터디 미흡으로 증거 불인정될 수 있습니다. 따라서 전자 서명, 타임스탬프, 증거 체인 기록이 필수.

### Q3. 침해 사실이 언론에 보도되기 전에 공지해야 하는가?
**해설**: 네, 의무입니다. 언론 보도 후 공지하는 것은 법적 문제입니다. 따라서 언론 담당팀과 동시에 진행해야 합니다.

<div align="center">

**[⬅️ 이전: 보안 로깅과 모니터링](./04-security-logging-monitoring.md)** | **[홈으로 🏠](../README.md)**

</div>
