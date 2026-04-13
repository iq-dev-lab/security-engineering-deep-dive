# 06. 최소 권한 원칙 (Principle of Least Privilege) — 필요한 권한만, 필요한 기간만

---

## 🎯 핵심 질문

새 개발자가 입사했을 때, 다음 중 어떤 권한을 부여해야 할까요?

**A) 현재 권한**
```
- 데이터베이스: root 계정 (모든 권한)
- AWS IAM: */* 와일드카드 권한
- Kubernetes: cluster-admin
- 파일 시스템: 755 (모든 디렉토리 읽기/쓰기/실행)
```

**B) 최소 권한**
```
- 데이터베이스: SELECT, INSERT, UPDATE (개발 DB에만, 프로덕션 제외)
- AWS IAM: s3:GetObject, s3:PutObject (특정 버킷만)
- Kubernetes: pods/logs, pods/describe (특정 네임스페이스만)
- 파일 시스템: 700 (자신의 홈 디렉토리만, 시스템 디렉토리 제외)
```

**명백히 B입니다.** 그런데 왜 많은 조직이 A를 선택할까요?

이것이 **최소 권한 원칙**의 본질입니다.

---

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

### 실제 사고 사례 1: 계약 만료 개발자의 무단 접근
2019년 한 핀테크 회사에서 **계약 관계가 종료된 개발자**가:

1. 회사에서 준 AWS 근본 계정 (Admin 권한)이 회수되지 않음
2. 3개월 후 접근으로 프로덕션 데이터베이스 변경
3. 결제 API를 조작하여 자신의 계정으로 수백만 원 송금

**피해액**: 약 2억 원 (데이터 복구 포함)

### 실제 사고 사례 2: 내부자의 데이터 탈취
한 의료기관에서:

1. 모든 직원에게 병원 전체 환자 데이터베이스 접근 권한 부여
2. 행정 직원이 의도적으로 환자 정보 5만 명분 수집
3. 불법 대출 업체에 정보 판매 (약 1억 원 거래)

**위반**: 개인정보보호법, 의료법

### 실제 사고 사례 3: 와일드카드 IAM 정책의 악용
한 스타트업에서:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",        // ← 모든 작업 허용!
      "Resource": "*"       // ← 모든 리소스!
    }
  ]
}
```

1. 개발자 계정이 탈취됨
2. 공격자가 EC2 대량 생성 → 암호화폐 채굴
3. AWS 청구액: $50,000 (정상: $5,000)

### 실제 사고 사례 4: 데이터베이스 권한 과다로 인한 실수
한 전자상거래 회사에서:

1. 모든 서버가 동일한 DB 계정 사용 (root 권한)
2. 개발 서버에서 실수로 DROP TABLE 명령 실행
3. **프로덕션 데이터베이스도 같은 권한이므로 영향**
4. 고객 주문 정보 손실 → 전체 시스템 중단

### 왜 위험한가?
- **내부자 위협**: 퇴사자, 악의적 직원의 피해
- **권한 상승**: 낮은 권한 서버 침투 후 전체 시스템 접근
- **실수의 영향 범위**: 한 실수가 전체 시스템 파괴
- **컴플라이언스 위반**: GDPR, PCI-DSS, HIPAA 등 규제 위반

---

## 😱 취약한 코드 (Before — 원리를 모를 때의 구현)

### 취약점 1: 모든 사용자에게 동일한 높은 권한 부여

```java
// 취약한 데이터베이스 설정
// application.yml
spring:
  datasource:
    url: jdbc:mysql://db.example.com:3306/production
    username: root              # ← 모든 개발자가 root!
    password: root_password     # ← 고정된 비밀번호!
    # 모든 권한: SELECT, INSERT, UPDATE, DELETE, DROP, CREATE, ALTER

// 취약한 점:
// - 모든 개발자가 프로덕션 DB에 root로 접근
// - 실수로 데이터 삭제 가능
// - 퇴사자도 접근 가능
// - 감시 추적 불가 (누가 했는지 알 수 없음)
```

### 취약점 2: AWS IAM 와일드카드 정책

```json
// 취약한 AWS IAM 정책
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AdminAccess",
      "Effect": "Allow",
      "Action": "*",                  // ← 모든 AWS 서비스
      "Resource": "*"                 // ← 모든 리소스
    }
  ]
}

// 또는 더 나쁜 경우:
{
  "Effect": "Allow",
  "Action": [
    "s3:*",                          // S3 모든 권한
    "ec2:*",                         // EC2 모든 권한
    "iam:*",                         // IAM 모든 권한 (사용자 생성!)
    "lambda:*"                       // Lambda 모든 권한
  ],
  "Resource": "*"
}

// 위험:
// - 자격증명 탈취 시 전체 AWS 계정 장악
// - 악의적 사용자가 IAM 정책 변경 가능
// - 비용 폭증 (제한 없는 리소스 생성)
```

### 취약점 3: Kubernetes RBAC 구성 부재

```yaml
# 취약한 Kubernetes: 모든 권한 부여
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: developer-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin  # ← 전체 클러스터 관리자 권한
subjects:
- kind: User
  name: developer@example.com
  apiGroup: rbac.authorization.k8s.io

# 결과:
# - 모든 개발자가 cluster-admin
# - 모든 namespace의 모든 Pod 접근
# - 리소스 삭제, 생성 모두 가능
# - 시크릿(비밀번호, API 키) 조회 가능
```

### 취약점 4: Spring Method Security 없음

```java
// 취약한 Spring 컨트롤러
@RestController
@RequestMapping("/api")
public class AdminController {
    
    @Autowired
    private UserService userService;
    
    // 문제 1: 역할 검증 없음
    @GetMapping("/users")
    public ResponseEntity<List<UserDto>> getAllUsers() {
        // 누구든 접근 가능!
        return ResponseEntity.ok(userService.findAll());
    }
    
    // 문제 2: 역할 검증 있지만 너무 관대함
    @PreAuthorize("isAuthenticated()")  // 로그인만 확인!
    @DeleteMapping("/users/{userId}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long userId) {
        userService.deleteById(userId);  // 모든 로그인 사용자가 삭제 가능!
        return ResponseEntity.noContent().build();
    }
    
    // 문제 3: 메서드 보안 없음
    @PostMapping("/system-config")
    public ResponseEntity<Void> updateSystemConfig(@RequestBody Config config) {
        // 누구든 시스템 설정 변경 가능!
        configService.save(config);
        return ResponseEntity.ok().build();
    }
}

// 더 나은 구현:
@RestController
@RequestMapping("/api/admin")
public class ProperAdminController {
    
    @Autowired
    private UserService userService;
    
    // 1. 명확한 역할 검증
    @PreAuthorize("hasRole('ADMIN')")  // ADMIN만
    @GetMapping("/users")
    public ResponseEntity<List<UserDto>> getAllUsers() {
        return ResponseEntity.ok(userService.findAll());
    }
    
    // 2. 더 높은 권한 필요
    @PreAuthorize("hasRole('SUPER_ADMIN')")  // SUPER_ADMIN만
    @DeleteMapping("/users/{userId}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long userId) {
        userService.deleteById(userId);
        return ResponseEntity.noContent().build();
    }
    
    // 3. 시스템 설정은 가장 높은 권한
    @PreAuthorize("hasRole('SYSTEM_ADMIN')")  // SYSTEM_ADMIN만
    @PostMapping("/system-config")
    public ResponseEntity<Void> updateSystemConfig(@RequestBody Config config) {
        configService.save(config);
        return ResponseEntity.noContent().build();
    }
}
```

---

## ✨ 방어 코드 (After — 공격 원리를 알고 설계한 구현)

### 방어 전략 1: 데이터베이스 계정 권한 최소화

```sql
-- Step 1: 애플리케이션별 전용 계정 생성

-- 개발 환경 (Dev Server)
CREATE USER 'app_dev'@'dev-server.example.com' IDENTIFIED BY 'complex_password_123!';
GRANT SELECT, INSERT, UPDATE ON development_db.* TO 'app_dev'@'dev-server.example.com';
-- DROP, ALTER, CREATE 권한 없음!

-- 프로덕션 환경 (Production Server)
CREATE USER 'app_prod'@'prod-server.example.com' IDENTIFIED BY 'complex_password_456!';
GRANT SELECT, INSERT, UPDATE ON production_db.* TO 'app_prod'@'prod-server.example.com';
-- DELETE 권한도 없음 (soft delete 권장)

-- 배치 작업 (Batch Server)
CREATE USER 'batch_job'@'batch-server.example.com' IDENTIFIED BY 'complex_password_789!';
GRANT SELECT, INSERT, UPDATE ON production_db.reporting_tables TO 'batch_job'@'batch-server.example.com';
-- 특정 테이블만!

-- Step 2: 테이블 단위 권한 분리
CREATE USER 'analytics'@'analytics-server.example.com' IDENTIFIED BY 'analytics_pass!';
GRANT SELECT ON production_db.analytics_data TO 'analytics'@'analytics-server.example.com';
-- 조회만 가능, 쓰기 불가

-- 읽기 전용 복제 서버 (Replica for read)
CREATE USER 'read_replica'@'read-replica.example.com' IDENTIFIED BY 'replica_pass!';
GRANT SELECT ON production_db.* TO 'read_replica'@'read-replica.example.com';
-- SELECT만 가능

-- Step 3: 감시 추적용 계정
CREATE USER 'backup_user'@'backup-server.example.com' IDENTIFIED BY 'backup_pass!';
GRANT SELECT, LOCK TABLES ON production_db.* TO 'backup_user'@'backup-server.example.com';
-- 백업에만 필요한 권한만

-- Step 4: 권한 검증
SHOW GRANTS FOR 'app_prod'@'prod-server.example.com';
-- Grants for app_prod@prod-server.example.com
-- GRANT SELECT, INSERT, UPDATE ON `production_db`.* TO `app_prod`@`prod-server.example.com`

-- Step 5: 권한 시간 제한 (선택사항)
-- MySQL 8.0+에서는 passwordExpiration, accountLocked 등 설정 가능
ALTER USER 'app_prod'@'prod-server.example.com' PASSWORD EXPIRE INTERVAL 90 DAY;
```

### 방어 전략 2: AWS IAM 정책의 세분화

```json
// Step 1: 역할별 정책 생성

// 개발자 역할: EC2와 S3의 특정 리소스만
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DevelopmentEC2Access",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:GetConsoleOutput",
        "ec2:GetPasswordData"
      ],
      "Resource": "arn:aws:ec2:*:ACCOUNT_ID:instance/i-dev-*"
      // 개발 인스턴스만 (i-dev- 접두사)
    },
    {
      "Sid": "DevelopmentS3Access",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::dev-bucket/*"
      // dev-bucket에만
    },
    {
      "Sid": "DenyProductionAccess",
      "Effect": "Deny",
      "Action": "*",
      "Resource": [
        "arn:aws:s3:::prod-bucket",
        "arn:aws:s3:::prod-bucket/*",
        "arn:aws:ec2:*:ACCOUNT_ID:instance/i-prod-*"
      ]
      // 프로덕션은 명시적으로 거부!
    }
  ]
}

// Step 2: DevOps 역할: 더 많은 권한 (하지만 여전히 제한)
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EC2Management",
      "Effect": "Allow",
      "Action": [
        "ec2:StartInstances",
        "ec2:StopInstances",
        "ec2:RebootInstances",
        "ec2:TerminateInstances"  // 중요: 종료 권한
      ],
      "Resource": "arn:aws:ec2:*:ACCOUNT_ID:instance/*",
      "Condition": {
        "StringEquals": {
          "aws:RequestedRegion": "ap-northeast-2"
        }
        // 한국 리전만
      }
    },
    {
      "Sid": "S3Management",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": "arn:aws:s3:::*"
      // 모든 S3 버킷 (삭제도 가능)
    },
    {
      "Sid": "DenyIAMChanges",
      "Effect": "Deny",
      "Action": [
        "iam:CreateUser",
        "iam:DeleteUser",
        "iam:AttachUserPolicy",
        "iam:PutUserPolicy"
      ]
      // IAM 정책 변경은 명시적으로 거부!
    }
  ]
}

// Step 3: SRE/보안팀: 가장 높은 권한 (감시 기능 포함)
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AdminAccess",
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    },
    {
      "Sid": "EnforceCloudTrailLogging",
      "Effect": "Deny",
      "Action": [
        "cloudtrail:DeleteTrail",
        "cloudtrail:StopLogging"
      ],
      "Resource": "*"
      // CloudTrail 로깅 중지 불가!
    }
  ]
}

// Step 4: 권한 경계 설정 (Permission Boundary)
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DeveloperBoundary",
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:RequestedRegion": ["ap-northeast-2", "us-east-1"]
        }
        // 특정 리전만
      }
    }
  ]
}
```

### 방어 전략 3: Kubernetes RBAC 세분화

```yaml
# Step 1: 네임스페이스별 역할 생성

apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: developer-role
  namespace: development
rules:
# Pod 조회 및 로그 조회만
- apiGroups: [""]
  resources: ["pods", "pods/logs"]
  verbs: ["get", "list", "watch"]
# Pod 실행 제한 (보안상)
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: ["create"]
  resourceNames: ["dev-*"]  # dev- 접두사 Pod만
# ConfigMap 조회만
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list"]
# 서비스/Deployment 조회만 (생성/수정 불가)
- apiGroups: ["apps"]
  resources: ["deployments", "statefulsets"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: developer-binding
  namespace: development
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: developer-role
subjects:
- kind: User
  name: developer@example.com
  apiGroup: rbac.authorization.k8s.io

---
# Step 2: 관리자 역할 (더 높은 권한)

apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: admin-role
rules:
# 모든 작업 허용 (하지만 특정 리소스만)
- apiGroups: ["", "apps", "batch"]
  resources: ["*"]
  verbs: ["*"]
  namespaceSelector:
    matchLabels:
      team: platform  # "team: platform" 레이블의 네임스페이스만
# 시크릿 접근 명시적으로 거부
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]  # 읽기만, 생성/수정은 불가
# 권한 변경 불가
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterrolebindings", "rolebindings"]
  verbs: []  # 아무 권한도 없음

---
# Step 3: 서비스 계정 (Pod용)

apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-service-account
  namespace: production

---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-role
  namespace: production
rules:
# ConfigMap만 읽기
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get"]
  resourceNames: ["app-config"]  # 특정 ConfigMap만
# 자신의 Pod 정보 조회
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-binding
  namespace: production
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: app-role
subjects:
- kind: ServiceAccount
  name: app-service-account
  namespace: production
```

### 방어 전략 4: Spring Method Security 및 계층별 권한

```java
// Step 1: Spring Security 설정
@Configuration
@EnableGlobalMethodSecurity(
    prePostEnabled = true,        // @PreAuthorize, @PostAuthorize
    securedEnabled = true,        // @Secured
    jsr250Enabled = true          // @RolesAllowed
)
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {
    
    @Override
    protected MethodSecurityExpressionHandler createExpressionHandler() {
        DefaultMethodSecurityExpressionHandler handler = 
            new DefaultMethodSecurityExpressionHandler();
        // 커스텀 권한 검증 Bean 추가 가능
        return handler;
    }
}

// Step 2: 계층별 API 권한 설정
@RestController
@RequestMapping("/api")
public class HierarchicalAccessController {
    
    @Autowired
    private UserService userService;
    
    @Autowired
    private AuditLog auditLog;
    
    // 레벨 1: 모든 로그인 사용자 (공개 API)
    @PreAuthorize("isAuthenticated()")
    @GetMapping("/public-data")
    public ResponseEntity<Data> getPublicData() {
        return ResponseEntity.ok(new Data("public"));
    }
    
    // 레벨 2: 일반 사용자 (자신의 데이터만)
    @PreAuthorize("isAuthenticated()")
    @GetMapping("/my-profile")
    public ResponseEntity<UserProfile> getMyProfile(
            @AuthenticationPrincipal CustomUserDetails userDetails) {
        User user = userService.findById(userDetails.getUserId());
        return ResponseEntity.ok(new UserProfile(user));
    }
    
    // 레벨 3: 매니저 (팀원 데이터 조회)
    @PreAuthorize("hasRole('MANAGER')")
    @GetMapping("/team/data")
    public ResponseEntity<List<Data>> getTeamData(
            @AuthenticationPrincipal CustomUserDetails userDetails) {
        
        User manager = userService.findById(userDetails.getUserId());
        
        // 매니저 권한 재검증
        if (!manager.hasRole("MANAGER")) {
            auditLog.logUnauthorizedAccess("GET /team/data", userDetails.getUserId());
            throw new AccessDeniedException("Manager role required");
        }
        
        return ResponseEntity.ok(userService.getTeamData(manager.getTeamId()));
    }
    
    // 레벨 4: 관리자 (모든 사용자 데이터 조회)
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/users")
    public ResponseEntity<List<UserDto>> getAllUsers(
            @AuthenticationPrincipal CustomUserDetails userDetails) {
        
        User admin = userService.findById(userDetails.getUserId());
        
        // ADMIN 권한 재검증
        if (!admin.hasRole("ADMIN")) {
            throw new AccessDeniedException("Admin role required");
        }
        
        auditLog.log("ADMIN_VIEW_ALL_USERS", userDetails.getUserId(), null);
        return ResponseEntity.ok(userService.getAllUsers());
    }
    
    // 레벨 5: 슈퍼 관리자 (데이터 삭제, 사용자 권한 변경)
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    @DeleteMapping("/admin/users/{userId}")
    public ResponseEntity<Void> deleteUser(
            @PathVariable Long userId,
            @AuthenticationPrincipal CustomUserDetails userDetails) {
        
        User superAdmin = userService.findById(userDetails.getUserId());
        
        // SUPER_ADMIN 권한 재검증
        if (!superAdmin.hasRole("SUPER_ADMIN")) {
            throw new AccessDeniedException("Super admin role required");
        }
        
        User targetUser = userService.findById(userId);
        
        // 자신 삭제 방지
        if (superAdmin.getId().equals(userId)) {
            throw new BusinessException("Cannot delete yourself");
        }
        
        auditLog.log("USER_DELETED", userDetails.getUserId(), 
                     String.format("Deleted user %d", userId));
        
        userService.deleteById(userId);
        return ResponseEntity.noContent().build();
    }
    
    // 레벨 6: 시스템 관리자 (시스템 설정, 감사)
    @PreAuthorize("hasRole('SYSTEM_ADMIN')")
    @PostMapping("/system/config")
    public ResponseEntity<SystemConfig> updateSystemConfig(
            @RequestBody SystemConfigRequest request,
            @AuthenticationPrincipal CustomUserDetails userDetails) {
        
        User sysAdmin = userService.findById(userDetails.getUserId());
        
        // SYSTEM_ADMIN 권한 재검증
        if (!sysAdmin.hasRole("SYSTEM_ADMIN")) {
            throw new AccessDeniedException("System admin role required");
        }
        
        auditLog.log("SYSTEM_CONFIG_CHANGED", userDetails.getUserId(),
                     "Config: " + request.toString());
        
        SystemConfig config = configService.updateConfig(request);
        return ResponseEntity.ok(config);
    }
}

// Step 3: 포스트 필터 (반환값 필터링)
@RestController
@RequestMapping("/api/data")
public class FilteredDataController {
    
    @Autowired
    private DataService dataService;
    
    // 반환값에서 민감한 정보 제거
    @PostFilter("filterObject.owner == principal.userId or hasRole('ADMIN')")
    @GetMapping
    public ResponseEntity<List<DataDto>> getData() {
        List<Data> allData = dataService.findAll();
        return ResponseEntity.ok(allData.stream()
            .map(DataDto::new)
            .toList());
    }
    
    // hasRole('ADMIN')이면 민감한 필드 포함
    @GetMapping("/{id}")
    public ResponseEntity<DataDto> getDataDetail(
            @PathVariable Long id,
            @AuthenticationPrincipal CustomUserDetails userDetails) {
        
        Data data = dataService.findById(id);
        
        if (userDetails.hasRole("ADMIN")) {
            // 관리자: 모든 정보 포함
            return ResponseEntity.ok(new DataDtoFull(data));
        } else {
            // 일반 사용자: 민감한 정보 제외
            return ResponseEntity.ok(new DataDtoPublic(data));
        }
    }
}
```

### 방어 전략 5: 권한 자동 해제 (Deprovisioning)

```java
// Step 1: 계약 만료 사용자 자동 비활성화
@Component
@EnableScheduling
public class DeprovisioningScheduler {
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private AuditLog auditLog;
    
    // 매일 자정에 실행
    @Scheduled(cron = "0 0 0 * * *")
    public void deactivateExpiredUsers() {
        List<User> expiredUsers = userRepository.findByContractEndDateBefore(
            LocalDate.now()
        );
        
        for (User user : expiredUsers) {
            if (user.isEnabled()) {
                // 1. 사용자 비활성화
                user.setEnabled(false);
                user.setDeactivatedAt(LocalDateTime.now());
                
                // 2. 모든 역할 박탈
                user.getRoles().clear();
                
                // 3. 활성 세션 무효화 (선택사항)
                // sessionRegistry.invalidateUserSessions(user.getUsername());
                
                // 4. 토큰 블랙리스트 추가
                // tokenBlacklistService.blacklistAllTokensForUser(user.getId());
                
                userRepository.save(user);
                
                // 5. 감사 로그
                auditLog.log("USER_DEPROVISIONED", null,
                    String.format("User %s deactivated (contract expired)", user.getUsername()));
                
                // 6. 알림 (IT 팀, 보안팀에)
                notifySecurityTeam(user);
            }
        }
    }
    
    private void notifySecurityTeam(User user) {
        // 이메일, Slack 등으로 알림
    }
}

// Step 2: 계약 갱신 시 권한 자동 부여
@Service
public class UserOnboardingService {
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private RoleRepository roleRepository;
    
    public User onboardUser(UserOnboardingRequest request) {
        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setContractStartDate(LocalDate.now());
        user.setContractEndDate(LocalDate.now().plusDays(365));  // 1년
        user.setEnabled(true);
        
        // 직책에 따라 자동으로 역할 부여
        List<Role> roles = getRolesForPosition(request.getPosition());
        user.setRoles(roles);
        
        User saved = userRepository.save(user);
        
        // 감사 로그
        auditLog.log("USER_ONBOARDED", null,
            String.format("User %s onboarded with roles: %s",
                user.getUsername(), roles));
        
        return saved;
    }
    
    private List<Role> getRolesForPosition(String position) {
        return switch (position) {
            case "DEVELOPER" -> List.of(
                roleRepository.findByName("ROLE_USER").orElseThrow(),
                roleRepository.findByName("ROLE_DEVELOPER").orElseThrow()
            );
            case "MANAGER" -> List.of(
                roleRepository.findByName("ROLE_USER").orElseThrow(),
                roleRepository.findByName("ROLE_MANAGER").orElseThrow()
            );
            case "ADMIN" -> List.of(
                roleRepository.findByName("ROLE_USER").orElseThrow(),
                roleRepository.findByName("ROLE_ADMIN").orElseThrow()
            );
            default -> List.of(
                roleRepository.findByName("ROLE_USER").orElseThrow()
            );
        };
    }
}
```

---

## 🔬 공격 원리 분석 (공격자 관점의 내부 동작)

### 공격 시나리오: 최소 권한이 없을 때

```
Step 1: 개발 서버 침투 (약한 보안)
┌────────────────────────────────┐
│ SSH 비밀번호: dev / dev123456  │
│ (약한 비밀번호, 공개 리포지토리) │
└────────────────────────────────┘
         ↓
Step 2: 데이터베이스 접근
┌────────────────────────────────┐
│ DB 계정: root / root_password   │
│ (모든 서버에서 동일한 계정)     │
│ (프로덕션과 개발 구별 없음)     │
└────────────────────────────────┘
         ↓
Step 3: 프로덕션 데이터 접근
┌────────────────────────────────┐
│ mysql -h prod-db.example.com \  │
│        -u root -p             │
│ → 프로덕션 DB 모든 데이터 접근! │
│                               │
│ SELECT * FROM users;  (고객 정보) │
│ SELECT * FROM payments;(결제 정보) │
│ SELECT * FROM secrets;(API 키)  │
└────────────────────────────────┘
         ↓
Step 4: 데이터 탈취 또는 변조
┌────────────────────────────────┐
│ DROP TABLE customers;          │
│ (프로덕션 데이터 모두 삭제!)    │
│                               │
│ 또는:                          │
│ UPDATE payments SET amount=0;  │
│ (결제 정보 변조)                │
└────────────────────────────────┘
```

### 최소 권한이 있을 때

```
Step 1: 개발 서버 침투 (동일)
┌────────────────────────────────┐
│ 개발 서버 접근 성공            │
└────────────────────────────────┘
         ↓
Step 2: 데이터베이스 접근 시도
┌────────────────────────────────┐
│ DB 계정: app_dev @ dev-server  │
│ (개발 서버에서만 접근 가능)    │
│                               │
│ mysql -h prod-db.example.com \ │
│        -u app_dev -p          │
│ → 거부! (호스트 제한)          │
│                               │
│ mysql -h dev-db.example.com \  │
│        -u app_dev -p          │
│ → 성공 (개발 DB에만)           │
└────────────────────────────────┘
         ↓
Step 3: 권한 확인
┌────────────────────────────────┐
│ SELECT * FROM production_db.*;  │
│ → 거부! (권한 없음)            │
│                               │
│ DROP TABLE dev_customers;     │
│ → 거부! (DROP 권한 없음)       │
│                               │
│ SELECT * FROM development_db.*;│
│ → 성공 (개발 DB 데이터만)      │
└────────────────────────────────┘
         ↓
Step 4: 피해 제한
┌────────────────────────────────┐
│ 개발 데이터만 접근 가능         │
│ (테스트 데이터이므로 영향 적음) │
│                               │
│ 프로덕션 데이터는 보호됨!      │
└────────────────────────────────┘
```

---

## 💻 실전 실험 (취약점 재현 → 공격 → 방어 검증)

### 실험 1: 데이터베이스 권한 격리 테스트

```sql
-- 테스트 환경 설정
CREATE DATABASE production_db;
CREATE DATABASE development_db;

-- 취약한 구성 (하나의 계정, 모든 권한)
CREATE USER 'app_weak'@'%' IDENTIFIED BY 'password123';
GRANT ALL PRIVILEGES ON *.* TO 'app_weak'@'%';

-- 방어된 구성 (계정별, 권한 최소화)
CREATE USER 'app_dev'@'dev-server.example.com' IDENTIFIED BY 'dev_password!';
GRANT SELECT, INSERT, UPDATE ON development_db.* TO 'app_dev'@'dev-server.example.com';

CREATE USER 'app_prod'@'prod-server.example.com' IDENTIFIED BY 'prod_password!';
GRANT SELECT, INSERT, UPDATE ON production_db.* TO 'app_prod'@'prod-server.example.com';

-- 테스트 1: 개발 계정이 프로덕션 접근 시도
-- mysql -h prod-db -u app_dev -p < dev_password!
-- USE production_db;
-- SELECT * FROM users;
-- → ERROR: Access denied (개발 계정이 프로덕션 DB 접근 불가)

-- 테스트 2: 개발 DB에서만 작업 가능
-- mysql -h dev-db -u app_dev -p < dev_password!
-- USE development_db;
-- SELECT * FROM users;
-- → OK (개발 DB에서는 가능)

-- 테스트 3: DROP 권한 없음
-- DROP TABLE development_db.users;
-- → ERROR: Access denied (DROP 권한 없음)
```

### 실험 2: AWS IAM 정책 테스트

```bash
#!/bin/bash

# AWS CLI로 권한 테스트

# Test 1: 개발자 - 개발 환경 S3 접근
aws s3 ls s3://dev-bucket --profile developer
# 성공

# Test 2: 개발자 - 프로덕션 S3 접근 시도
aws s3 ls s3://prod-bucket --profile developer
# 실패: "Access Denied"

# Test 3: 개발자 - EC2 프로덕션 인스턴스 접근 시도
aws ec2 describe-instances \
    --filters "Name=instance-id,Values=i-prod-12345" \
    --profile developer
# 실패: "An error occurred (UnauthorizedOperation)"

# Test 4: DevOps - EC2 관리 작업 (리전 제한)
aws ec2 stop-instances --instance-ids i-12345 \
    --region ap-northeast-2 --profile devops
# 성공

# Test 5: DevOps - 다른 리전 시도
aws ec2 stop-instances --instance-ids i-12345 \
    --region us-east-1 --profile devops
# 실패: "AccessDenied" (리전 제한)

# Test 6: 개발자 - IAM 정책 생성 시도
aws iam put-user-policy --user-name attacker \
    --policy-name ElevatedAccess \
    --policy-document file://policy.json \
    --profile developer
# 실패: "User: developer is not authorized to perform: iam:PutUserPolicy"
```

### 실험 3: Kubernetes RBAC 테스트

```bash
#!/bin/bash

# Kubernetes에서 권한 테스트

# Test 1: 개발자 - 자신의 namespace에서 Pod 조회
kubectl get pods -n development --as=developer@example.com
# 성공: Pod 목록 표시

# Test 2: 개발자 - 프로덕션 namespace 접근 시도
kubectl get pods -n production --as=developer@example.com
# 실패: "Error from server (Forbidden)"

# Test 3: 개발자 - Pod 삭제 시도
kubectl delete pod my-pod -n development --as=developer@example.com
# 실패: "Error from server (Forbidden)"
# (권한에 delete 없음)

# Test 4: 개발자 - 시크릿 조회 시도
kubectl get secrets -n development --as=developer@example.com
# 실패: "Error from server (Forbidden)"
# (시크릿 접근 권한 없음)

# Test 5: 관리자 - 모든 namespace 접근
kubectl get pods --all-namespaces --as=admin@example.com
# 성공: 모든 Pod 표시

# Test 6: 권한 확인
kubectl auth can-i get pods \
    --as=developer@example.com \
    -n development
# yes

kubectl auth can-i create deployments \
    --as=developer@example.com \
    -n development
# no (생성 권한 없음)
```

---

## 📊 공격 성공 조건 vs 방어 성공 조건 비교

| 항목 | 공격 성공 조건 | 방어 성공 조건 |
|------|--------------|--------------|
| **DB 계정** | 모든 권한 (root) | 최소 권한 (SELECT, INSERT, UPDATE만) |
| **접근 호스트** | 모든 호스트에서 접근 | 특정 서버에서만 접근 가능 |
| **권한 범위** | 모든 데이터베이스 | 특정 DB만 |
| **작업 권한** | DROP, ALTER, TRUNCATE 가능 | 읽기/쓰기만 (수정 불가) |
| **피해 규모** | 전체 시스템 | 제한된 범위 |
| **감시** | 누가 했는지 추적 불가 | 계정별 추적 가능 (감사 로그) |
| **퇴사자 접근** | 여전히 접근 가능 | 자동 비활성화 |

---

## ⚖️ 트레이드오프 (보안 강화 vs 사용성/성능)

### 트레이드오프 1: 복잡성 vs 보안

```
최소 권한 (보안):
+ 내부자 위협 감소
+ 침입자 피해 제한
- 권한 관리 복잡성 증가
- 요청 처리 시간 증가

모든 권한 (편의성):
+ 개발 속도 향상
+ 관리 간단
- 보안 위험 증가
- 실수의 영향 범위 확대
```

**해결책**: 자동화된 권한 관리

```java
@Component
@EnableScheduling
public class AutomatedPrivilegeManagement {
    
    @Autowired
    private UserRepository userRepository;
    
    // 역할별 권한을 DB에서 자동으로 부여
    @Scheduled(cron = "0 0 * * * *")  // 매시간
    public void syncRolesWithDatabase() {
        List<User> users = userRepository.findAll();
        
        for (User user : users) {
            // 직책에 맞는 권한 자동 부여
            Set<Role> expectedRoles = determineRolesForPosition(user.getPosition());
            
            // 권한 변경 (추가/제거)
            user.getRoles().retainAll(expectedRoles);  // 불필요한 권한 제거
            user.getRoles().addAll(expectedRoles);     // 필요한 권한 추가
            
            userRepository.save(user);
        }
    }
    
    private Set<Role> determineRolesForPosition(String position) {
        // 직책에 따른 권한 자동 결정
        return switch (position) {
            case "DEVELOPER" -> Set.of(
                new Role("ROLE_USER"),
                new Role("ROLE_DEVELOPER")
            );
            case "DBA" -> Set.of(
                new Role("ROLE_USER"),
                new Role("ROLE_DBA")
            );
            default -> Set.of(new Role("ROLE_USER"));
        };
    }
}
```

### 트레이드오프 2: 성능 vs 추적

```
감시 강화 (보안):
+ 모든 작업 감사 로그
+ 누가 언제 뭘 했는지 추적
- 로그 저장소 용량 증가
- 쿼리 성능 저하

감시 최소화 (성능):
+ 빠른 처리
+ 저장소 용량 절약
- 침입 탐지 어려움
- 법적 추적 불가
```

**해결책**: 선택적 감시

```java
@Component
public class AuditLogService {
    
    @Autowired
    private AuditLogRepository auditLogRepository;
    
    public void logAction(String actionType, Long userId, String details) {
        // 민감한 작업만 로깅
        if (isSensitiveAction(actionType)) {
            AuditLog log = new AuditLog();
            log.setActionType(actionType);
            log.setUserId(userId);
            log.setDetails(details);
            log.setTimestamp(LocalDateTime.now());
            
            auditLogRepository.save(log);
        }
    }
    
    private boolean isSensitiveAction(String actionType) {
        Set<String> sensitiveActions = Set.of(
            "DELETE",
            "USER_DELETED",
            "ROLE_CHANGED",
            "ACCESS_DENIED",
            "SYSTEM_CONFIG_CHANGED"
        );
        
        return sensitiveActions.contains(actionType);
    }
}
```

---

## 📌 핵심 정리

1. **최소 권한 원칙**:
   - 각 사용자/서버는 업무에 필요한 최소 권한만 부여
   - 시간 제한 (계약 기간) 설정
   - 정기적으로 권한 검토

2. **계층별 권한 분리**:
   - 개발자 ≠ 관리자 ≠ 시스템 관리자
   - 각 계층은 명확한 역할 정의
   - 권한 상향은 예외적, 권한 하향은 기본

3. **기술적 구현**:
   - DB: 계정별 호스트/DB/테이블 권한 분리
   - AWS: IAM 와일드카드 제거, 리소스 지정
   - Kubernetes: 네임스페이스, Role 활용
   - Spring: @PreAuthorize, 메서드 보안

4. **자동화**:
   - 입사자 권한 자동 부여
   - 퇴사자 권한 자동 회수
   - 정기적 권한 감사 및 동기화

5. **감시 추적**:
   - 민감한 작업은 모두 로깅
   - 누가, 언제, 뭘, 왜 했는지 기록
   - 정기적 감사 로그 검토

---

## 🤔 생각해볼 문제 (+ 해설)

### 문제 1: 개발자가 "이 권한이 필요하다"고 주장하면?

**상황**: "프로덕션 DB DROP 권한이 필요해요"

**해설**:
필요성을 검증한 후, 대안을 찾으세요:

```
대안 1: 백업에서 복구 (권장)
- DROP 대신 soft delete (플래그 변경)
- 복구 가능하도록 설계

대안 2: 임시 권한 부여
- 제한된 시간동안만 권한 부여
- DROP 실행 후 즉시 권한 회수
- 작업 완료 후 감사 로그 검토

대안 3: DBA를 통한 간접 실행
- 개발자가 요청
- DBA가 실행 및 로깅
```

---

### 문제 2: 마이크로서비스에서 각 서비스가 다른 DB를 쓰면?

**상황**: User 서비스, Order 서비스가 각각의 DB 사용

**해설**:
각 서비스의 데이터베이스 계정도 분리해야 합니다:

```
App_User_Service → DB_Users (user_app@dev-server)
                → SELECT, INSERT, UPDATE users, roles, profiles
                → 다른 테이블 접근 불가

App_Order_Service → DB_Orders (order_app@dev-server)
                 → SELECT, INSERT, UPDATE orders, items
                 → users 테이블 접근 불가
```

---

### 문제 3: 배치 작업은 누가 어떻게 실행하나?

**상황**: 매일 밤 리포트 생성 배치 작업

**해설**:
배치용 전용 계정을 만들고, 필요한 권한만 부여하세요:

```sql
CREATE USER 'batch_report'@'batch-server.example.com' 
IDENTIFIED BY 'batch_password!';

GRANT SELECT ON production_db.orders TO 'batch_report'@'batch-server.example.com';
GRANT SELECT ON production_db.items TO 'batch_report'@'batch-server.example.com';
GRANT INSERT ON production_db.reports TO 'batch_report'@'batch-server.example.com';

-- DELETE, DROP, ALTER 권한 없음!
```

<div align="center">

**[⬅️ 이전: JWT 권한 클레임 검증](./05-jwt-claims-validation.md)** | **[홈으로 🏠](../README.md)** | **[다음: Chapter 6 — SSRF와 클라우드 메타데이터 탈취 ➡️](../ssrf-data-exposure/01-ssrf-cloud-metadata.md)**

</div>
