# Detect Bot

![Detect Bot Logo](assets/detectbot-logo.png)

`Detect Bot`은 DMZ 구간 웹 서버에서 웹 서비스 경로를 수집하고, 해당 경로 아래 파일을 스캔해 노출 위험이 있는 파일이나 민감 정보 흔적을 JSON 리포트로 남기는 Go 기반 점검 도구입니다.

현재 저장소 모듈 경로는 `github.com/heartblast/detect_bot`입니다.

## 무엇을 하나요

- `nginx -T` 출력에서 `root`, `alias` 경로를 추출합니다.
- `apachectl -S` 출력에서 `DocumentRoot` 경로를 추출합니다.
- `--watch-dir`로 수동 감시 경로를 추가할 수 있습니다.
- 수집한 루트 경로를 순회하며 파일 메타데이터와 일부 내용까지 검사합니다.
- 결과를 JSON 리포트로 저장하거나 stdout으로 출력할 수 있습니다.
- 선택적으로 Kafka로 요약 이벤트를 전송할 수 있습니다.

## 현재 구현 기준 주요 기능

### 1. 스캔 루트 수집

- Nginx: `root`, `alias`
- Apache: `DocumentRoot`
- Manual: `--watch-dir`

수집한 루트가 정규화되며, 가능한 경우 symlink 실제 경로도 함께 기록합니다.

### 2. 파일 시스템 스캔

현재 스캔 시 아래 제어값을 지원합니다.

- `--max-depth`: 재귀 깊이 제한
- `--exclude`: 제외 경로 prefix
- `--newer-than-h`: 최근 N시간 내 수정 파일만 대상
- `--workers`: 병렬 스캔 워커 수
- `--follow-symlink`: symlink/reparse point 추적 여부
- `--max-size-mb`: MIME sniff 및 해시 계산 시 읽을 최대 파일 크기

### 3. 기본 룰

현재 코드에서 기본 활성화되는 룰은 아래 4가지입니다.

- `allowlist`
- `high_risk_ext`
- `large_file`
- `ext_mime_mismatch`

각 룰이 만들어내는 대표 reason 코드는 아래와 같습니다.

- `mime_not_in_allowlist`
- `ext_not_in_allowlist`
- `high_risk_extension`
- `large_file_in_web_path`
- `ext_mime_mismatch_image`
- `ext_mime_mismatch_archive`

### 4. 콘텐츠 기반 민감정보 탐지

`--content-scan`을 켜면 텍스트 계열 파일 일부를 읽어 아래 범주의 패턴을 탐지합니다.

- DB/서비스 연결 문자열
- 비밀번호, 토큰, API 키 같은 자격 증명
- private key 블록
- 이메일, IP, 내부 주소 흔적
- 위험 조합 패턴

대표 매칭 코드 예시:

- `connection_jdbc_url`
- `connection_redis_uri`
- `connection_mongodb_uri`
- `credential_password`
- `credential_api_key`
- `private_key_rsa`
- `internal_endpoint_private_ip`
- `combo_jdbc_with_credentials`

### 5. PII 탐지

`--pii-scan`을 켜면 개인정보 패턴을 탐지합니다.

- 주민등록번호
- 외국인등록번호
- 여권번호
- 운전면허번호
- 카드번호
- 계좌번호
- 휴대전화번호
- 이메일

대표 매칭 코드 예시:

- `resident_registration_number`
- `foreigner_registration_number`
- `passport_number`
- `drivers_license`
- `credit_card`
- `bank_account`
- `mobile_phone`
- `email`

## 제한사항

- MIME 판별은 `net/http.DetectContentType` 기반의 샘플 sniff 방식입니다.
- 콘텐츠/PII 스캔은 파일 전체가 아니라 제한된 샘플만 읽습니다.
- `--hash` 플래그와 `sha256` 필드는 존재하지만 현재 구현에서는 `sha256` 값이 실제로 채워지지 않습니다.
- Kafka의 SASL 관련 플래그와 설정은 있으나 현재는 stub 상태이며 실제 인증 로직은 구현되어 있지 않습니다.
- Kafka TLS는 `InsecureSkipVerify: true`로 동작합니다.

## 설치 및 빌드

- Build/CI toolchain: Go 1.26.1
- `go.mod` language version: Go 1.25.0

### 로컬 빌드

```bash
go build -o detectbot ./cmd/detectbot
```

### Windows PowerShell

```powershell
go build -o detectbot.exe .\cmd\detectbot
```

## DetectBot Portal

`detectbot_portal`은 공통 SQLAlchemy 모델과 service/repository 구조를 통해 SQLite와 PostgreSQL을 모두 지원합니다.

포털 상세 설정은 [detectbot_portal/README.md](/d:/golang/go-workspace/dmz_webroot_scanner/detectbot_portal/README.md)에 정리돼 있습니다.

### 배포용 빌드 스크립트

저장소에는 아래 스크립트가 포함되어 있습니다.

- `build.sh`
- `build.ps1`

`build.sh` 기준 산출물 예시:

- `dist/detectbot_windows_amd64_v1_1_3.exe`
- `dist/detectbot_linux_amd64_v1_1_3`
- `dist/detectbot_darwin_amd64_v1_1_3`
- `dist/detectbot_darwin_arm64_v1_1_3`

## 빠른 사용 예시

### Nginx dump 기반

```bash
nginx -T 2>&1 | ./detectbot \
  --server-type nginx \
  --nginx-dump - \
  --scan \
  --out /tmp/report.json
```

### Apache dump 기반

```bash
apachectl -S 2>&1 | ./detectbot \
  --server-type apache \
  --apache-dump - \
  --scan \
  --out /tmp/report.json
```

### 수동 경로 기반

```bash
./detectbot \
  --server-type manual \
  --watch-dir /var/www/html \
  --watch-dir /srv/uploads \
  --scan \
  --out /tmp/report.json
```

### 콘텐츠 스캔 포함

```bash
./detectbot \
  --server-type manual \
  --watch-dir /var/www/html \
  --scan \
  --content-scan \
  --content-ext .yaml \
  --content-ext .env \
  --out /tmp/report-content.json
```

### PII 스캔 포함

```bash
./detectbot \
  --server-type manual \
  --watch-dir /var/www/html \
  --scan \
  --pii-scan \
  --pii-ext .json \
  --pii-ext .txt \
  --pii-mask \
  --pii-store-sample \
  --out /tmp/report-pii.json
```

## CLI 옵션

### 입력 옵션

| 옵션 | 설명 | 실제 동작 | 사용 예시 | 기본값/주의사항 |
| --- | --- | --- | --- | --- |
| `--server-type nginx\|apache\|manual` | 스캔 대상 경로를 어떤 방식으로 수집할지 지정합니다. | `nginx`는 `--nginx-dump`, `apache`는 `--apache-dump`, `manual`은 최소 1개 이상의 `--watch-dir`가 필요합니다. 값이 없으면 dump 옵션 존재 여부로 nginx/apache를 보정하거나, 지정된 `watch-dir`만 수동 경로로 추가합니다. | `--server-type manual --watch-dir /var/www/html` | 미지정 가능. 잘못된 조합은 실행 초기에 오류로 중단됩니다. |
| `--nginx-dump <path\|->` | `nginx -T` 출력에서 웹 루트 경로를 추출합니다. | 파일 경로나 `-` stdin을 읽고 `root`, `alias` 지시어를 파싱해 scan root에 추가합니다. 이 옵션이 있으면 `server_type`이 비어 있을 때 `nginx`로 설정됩니다. | `nginx -T 2>&1 \| ./detectbot --nginx-dump - --scan` | `--server-type nginx`와 함께 쓰는 것이 명확합니다. |
| `--apache-dump <path\|->` | `apachectl -S` 출력에서 DocumentRoot 경로를 추출합니다. | 파일 경로나 `-` stdin을 읽고 Apache DocumentRoot 정보를 scan root에 추가합니다. 이 옵션이 있으면 `server_type`이 비어 있을 때 `apache`로 설정됩니다. | `apachectl -S 2>&1 \| ./detectbot --apache-dump - --scan` | `--server-type apache`와 함께 쓰는 것이 명확합니다. |
| `--watch-dir <path>` | 사용자가 직접 점검할 디렉터리를 추가합니다. | 반복 지정한 모든 경로를 `manual` source의 scan root로 추가합니다. nginx/apache dump에서 추출한 경로와 함께 사용할 수도 있습니다. | `--watch-dir /var/www/html --watch-dir /srv/uploads` | 반복 가능. `--server-type manual`에서는 최소 1개가 필요합니다. |
| `--config <yaml\|json>` | YAML 또는 JSON 설정 파일을 먼저 읽습니다. | 플래그 등록 전에 설정 파일을 로드한 뒤 CLI 인자로 덮어씁니다. `.yaml`, `.yml`, `.json`만 지원합니다. | `--config sample_config.yaml --watch-dir /extra/path` | CLI 값이 설정 파일보다 우선합니다. `watch_dir`, `content_ext`, `pii_ext`, `output` alias도 지원합니다. |

### 스캔 옵션

| 옵션 | 설명 | 실제 동작 | 사용 예시 | 기본값/주의사항 |
| --- | --- | --- | --- | --- |
| `--scan` | 발견한 root 아래 파일을 실제로 검사합니다. | 켜져 있으면 파일 시스템을 순회하고 활성 룰을 평가해 findings를 생성합니다. 꺼져 있으면 root 목록만 리포트에 기록합니다. | `--scan --out /tmp/report.json` | 기본값은 `false`입니다. `--preset`을 쓰면 대부분 `true`로 설정됩니다. |
| `--exclude <path>` | 특정 경로 이하를 스캔에서 제외합니다. | 경로를 정규화한 뒤 prefix로 비교합니다. 디렉터리가 제외되면 하위 탐색도 건너뜁니다. Windows에서는 대소문자를 구분하지 않습니다. | `--exclude /var/www/html/cache --exclude /var/www/html/tmp` | 반복 가능. 정확한 경로 또는 그 하위 경로가 제외됩니다. |
| `--max-depth <n>` | root 기준 재귀 탐색 깊이를 제한합니다. | `depth(root, path) > n`인 경로를 건너뜁니다. 디렉터리면 하위 탐색도 중단합니다. | `--max-depth 5` | 기본값은 `12`입니다. 코드상 `0`은 제한 없음처럼 비교되지만 기본값 적용 단계에서 `12`로 채워집니다. |
| `--newer-than-h <hours>` | 최근 N시간 안에 수정된 파일만 finding 평가 대상으로 삼습니다. | 파일의 `mod_time`이 현재 시각 기준 N시간보다 오래되면 MIME/룰 평가 전에 제외합니다. | `--newer-than-h 24` | 기본값 `0`은 시간 필터를 사용하지 않습니다. |
| `--workers <n>` | 파일 평가 worker 수를 지정합니다. | 파일 경로 채널을 여러 goroutine이 병렬로 소비해 컨텍스트 생성과 룰 평가를 수행합니다. | `--workers 8` | 기본값은 `4`입니다. `0` 이하로 들어오면 기본값 적용 후 `4`가 됩니다. |
| `--hash` | finding에 SHA256을 계산하려는 옵션입니다. | 현재 코드에는 플래그와 설정 필드, 해시 계산 함수가 있지만 finding 생성 경로에서 호출되지 않습니다. | `--hash` | 현재 리포트의 `sha256` 값은 이 옵션만으로 채워지지 않습니다. |
| `--max-size-mb <n>` | 대용량 파일 읽기 제한을 설정하려는 옵션입니다. | 현재 코드에서는 설정값과 리포트 config에는 남지만 MIME sniff, hash, content scan 제한에 직접 사용되지 않습니다. | `--max-size-mb 100` | 기본값은 `100`입니다. 실제 대용량 판단 룰은 코드상 50MB 고정 기준을 사용합니다. |
| `--follow-symlink` | symlink, Windows reparse point를 따라갈지 정합니다. | 꺼져 있으면 symlink 파일/디렉터리를 건너뜁니다. Windows에서는 접합점/마운트 포인트 같은 reparse point도 보수적으로 건너뜁니다. | `--follow-symlink` | 기본값은 `false`입니다. 순환 경로나 예상 밖 영역 스캔 위험이 있어 신중히 사용합니다. |

### 정책/룰 옵션

| 옵션 | 설명 | 실제 동작 | 사용 예시 | 기본값/주의사항 |
| --- | --- | --- | --- | --- |
| `--allow-mime-prefix <prefix>` | 허용할 MIME 타입 prefix를 지정합니다. | `allowlist` 룰이 sniff된 MIME과 비교합니다. 값이 정확히 같거나, `/`, `-`로 끝나는 prefix와 앞부분이 맞으면 허용됩니다. 허용되지 않으면 `mime_not_in_allowlist` finding 사유가 붙습니다. | `--allow-mime-prefix text/html --allow-mime-prefix image/` | 반복 가능. 기본값은 html/css/js/json, image/font, xml, text/plain 계열입니다. |
| `--allow-ext <ext>` | 허용할 파일 확장자를 지정합니다. | `allowlist` 룰이 파일 확장자를 소문자로 비교합니다. 허용되지 않은 확장자는 `ext_not_in_allowlist` 사유가 붙습니다. | `--allow-ext .html --allow-ext .css --allow-ext .js` | 반복 가능. 기본값은 정적 웹 자산 중심 확장자입니다. 확장자가 없는 파일은 확장자 allowlist 위반을 만들지 않습니다. |
| `--enable-rules <name>` | 룰 이름을 명시적으로 활성화 목록에 추가합니다. | 기본 룰셋을 만든 뒤 enable/disable map으로 필터링합니다. 현재 생성되는 룰 이름은 `allowlist`, `high_risk_ext`, `large_file`, `ext_mime_mismatch`, `secret_patterns`, `pii_patterns`입니다. | `--enable-rules secret_patterns,pii_patterns` | 반복 또는 comma-separated 가능. 단, content/PII 룰은 각각 `--content-scan`, `--pii-scan`이 켜져야 룰셋에 생성됩니다. |
| `--disable-rules <name>` | 특정 룰을 비활성화합니다. | 룰 이름을 `false`로 표시한 뒤 해당 룰을 최종 룰셋에서 제외합니다. | `--disable-rules large_file --disable-rules ext_mime_mismatch` | 반복 또는 comma-separated 가능. `disable`이 같은 이름의 `enable`보다 나중에 적용됩니다. |
| `--preset safe\|balanced\|deep\|handover\|offboarding` | 미리 정의된 스캔 강도/목적별 설정을 적용합니다. | 설정 파일과 CLI 파싱 후, 아직 비어 있는 일부 값(`scan`, `max_depth`, `workers`, `content_scan`, `content_max_bytes`)을 preset 값으로 채웁니다. | `--preset balanced --watch-dir /var/www/html` | 기본값 없음. CLI에서 이미 지정한 값은 preset이 덮어쓰지 않습니다. `deep`의 `max_depth=0`은 이후 기본값 처리로 `12`가 됩니다. |

### 콘텐츠 스캔 옵션

| 옵션 | 설명 | 실제 동작 | 사용 예시 | 기본값/주의사항 |
| --- | --- | --- | --- | --- |
| `--content-scan` | 파일 본문에서 비밀정보/접속정보 패턴을 찾습니다. | `secret_patterns` 룰을 룰셋에 추가합니다. 대상 확장자와 크기 제한을 통과한 텍스트성 파일에서 샘플을 읽고 credential, connection string, private key, 내부 endpoint 등 패턴을 평가합니다. | `--content-scan --content-ext .env --content-ext .yaml` | 기본값은 `false`입니다. preset `balanced`, `deep`, `offboarding`은 켤 수 있습니다. |
| `--content-max-bytes <n>` | 콘텐츠 스캔에서 파일당 읽을 최대 바이트 수를 지정합니다. | 샘플 읽기 상한으로 사용됩니다. 파일이 이 값보다 크면 앞부분만 읽고 finding에는 `content_flags: truncated`가 기록될 수 있습니다. | `--content-max-bytes 131072` | 기본값은 `65536`입니다. PII 스캔도 함께 켜져 있으면 더 큰 값이 통합 샘플 읽기 상한으로 사용됩니다. |
| `--content-max-size-kb <n>` | 콘텐츠 스캔 대상 파일의 최대 크기를 KB로 제한합니다. | 파일 크기가 제한보다 크면 본문 샘플을 읽지 않습니다. PII 스캔 제한과 함께 비교해 더 큰 제한이 통합 샘플 읽기 기준으로 사용됩니다. | `--content-max-size-kb 2048` | 기본값은 `1024`입니다. |
| `--content-ext <ext>` | 콘텐츠 스캔 대상 확장자를 지정합니다. | 지정된 확장자를 소문자로 비교해 텍스트성 스캔 대상 여부를 판단합니다. | `--content-ext .env --content-ext .properties` | 반복 가능. 기본값은 `.yaml`, `.json`, `.xml`, `.properties`, `.conf`, `.env`, `.ini`, `.txt`, `.config`, `.cfg`, `.toml` 등입니다. |

### PII 스캔 옵션

| 옵션 | 설명 | 실제 동작 | 사용 예시 | 기본값/주의사항 |
| --- | --- | --- | --- | --- |
| `--pii-scan` | 파일 본문에서 개인정보 패턴을 찾습니다. | `pii_patterns` 룰을 룰셋에 추가합니다. 주민등록번호, 외국인등록번호, 여권번호, 운전면허번호, 카드번호, 계좌번호, 휴대전화번호, 이메일 패턴을 평가합니다. | `--pii-scan --pii-mask --pii-store-sample` | 기본값은 `false`입니다. preset만으로는 현재 코드에서 자동 활성화되지 않습니다. |
| `--pii-ext <ext>` | PII 스캔 대상 확장자를 지정합니다. | 확장자 앞에 `.`이 없으면 코드에서 자동으로 붙인 뒤 비교합니다. | `--pii-ext json --pii-ext .txt` | 반복 가능. 기본값은 `.yaml`, `.json`, `.xml`, `.properties`, `.conf`, `.env`, `.ini`, `.txt`, `.log`, `.csv`, `.tsv` 등입니다. |
| `--pii-max-size-kb <n>` | PII 스캔 대상 파일의 최대 크기를 KB로 제한합니다. | 파일 크기가 제한보다 크면 본문 샘플을 읽지 않습니다. 콘텐츠 스캔 제한과 함께 비교해 더 큰 제한이 통합 샘플 읽기 기준으로 사용됩니다. | `--pii-max-size-kb 512` | 기본값은 `256`입니다. |
| `--pii-max-bytes <n>` | PII 스캔에서 파일당 읽을 최대 바이트 수를 지정합니다. | 샘플 읽기 상한으로 사용됩니다. 콘텐츠 스캔도 함께 켜져 있으면 더 큰 값이 통합 샘플 읽기 상한으로 사용됩니다. | `--pii-max-bytes 65536` | 기본값은 `65536`입니다. |
| `--pii-max-matches <n>` | PII 룰별로 저장할 최대 매칭 수를 제한합니다. | PII 룰에 `MaxMatches`로 전달되어 결과에 담는 매칭 개수를 제한합니다. | `--pii-max-matches 3` | 기본값은 `5`입니다. |
| `--pii-mask` | PII 값을 마스킹해 결과에 저장합니다. | PII 룰의 `MaskSensitive` 설정으로 전달되어 evidence 값을 가린 형태로 남깁니다. | `--pii-mask` | 기본값은 `false`입니다. 민감정보 리포트 공유 시 권장됩니다. |
| `--pii-store-sample` | PII 탐지 샘플을 결과에 저장합니다. | PII 룰의 `StoreSample` 설정으로 전달되어 evidence 저장 여부에 영향을 줍니다. | `--pii-store-sample` | 기본값은 `false`입니다. `--pii-mask`와 함께 쓰는 것이 안전합니다. |
| `--pii-context-keywords` | 주변 문맥 키워드를 PII 판단에 활용합니다. | PII 룰의 `UseContextKeywords` 설정으로 전달되어 주민번호/계좌번호 등 숫자 패턴의 탐지 신뢰도 판단에 사용됩니다. | `--pii-context-keywords` | 기본값은 `false`입니다. |

### 출력 옵션

| 옵션 | 설명 | 실제 동작 | 사용 예시 | 기본값/주의사항 |
| --- | --- | --- | --- | --- |
| `--out <path\|->` | JSON 리포트 출력 위치를 지정합니다. | `-`이면 stdout으로 pretty JSON을 쓰고, 그 외에는 해당 경로에 파일을 생성합니다. 로그는 stderr로 출력됩니다. | `--out /tmp/report.json` 또는 `--out -` | 현재 기본값이 비어 있으면 파일 생성 경로도 비어 오류가 날 수 있으므로 명시하는 것이 안전합니다. |

### Kafka 옵션

| 옵션 | 설명 | 실제 동작 | 사용 예시 | 기본값/주의사항 |
| --- | --- | --- | --- | --- |
| `--kafka-enabled` | 스캔 완료 후 Kafka 이벤트 전송을 켭니다. | 로컬 JSON 리포트 작성 후 요약 이벤트를 Kafka로 전송합니다. 전송 실패는 경고 로그만 남기고 스캔 결과 생성 자체는 중단하지 않습니다. | `--kafka-enabled --kafka-brokers broker1:9092 --kafka-topic dmz.scan.findings` | 기본값은 `false`입니다. brokers와 topic이 없으면 전송 오류가 납니다. |
| `--kafka-brokers <a,b,c>` | Kafka 브로커 목록을 지정합니다. | comma-separated 또는 반복 입력을 받아 `kgo.SeedBrokers`에 전달합니다. | `--kafka-brokers broker1:9092,broker2:9092` | 반복 가능. `--kafka-enabled` 사용 시 필요합니다. |
| `--kafka-topic <topic>` | 이벤트를 발행할 Kafka topic을 지정합니다. | 요약 이벤트 record의 topic으로 사용됩니다. | `--kafka-topic dmz.scan.findings` | `--kafka-enabled` 사용 시 필요합니다. |
| `--kafka-client-id <id>` | Kafka client id를 지정합니다. | 값이 있으면 Kafka 클라이언트 옵션에 `ClientID`로 설정합니다. | `--kafka-client-id detectbot-web01` | 기본값은 빈 값입니다. |
| `--kafka-tls` | Kafka 연결에 TLS를 사용합니다. | TLS dial config를 추가합니다. 현재 코드는 `InsecureSkipVerify: true`로 동작합니다. | `--kafka-tls` | 기본값은 `false`입니다. 인증서 검증을 건너뛰므로 운영 적용 전 검토가 필요합니다. |
| `--kafka-sasl-enabled` | Kafka SASL 인증 사용을 표시합니다. | 환경변수에서 비밀번호를 읽고 안내 로그를 출력하지만, 실제 SASL 인증 옵션은 아직 구현되어 있지 않습니다. | `--kafka-sasl-enabled --kafka-username detectbot --kafka-password-env KAFKA_PASSWORD` | 현재 stub 상태입니다. SASL 필수 브로커에서는 인증되지 않을 수 있습니다. |
| `--kafka-username <user>` | SASL 사용자명을 지정합니다. | SASL 안내 로그에 사용되며, 현재 실제 인증 옵션으로는 전달되지 않습니다. | `--kafka-username detectbot` | `--kafka-sasl-enabled`와 함께 쓰는 값입니다. |
| `--kafka-password-env <env>` | Kafka 비밀번호를 담은 환경변수 이름을 지정합니다. | `os.Getenv()`으로 해당 환경변수를 읽지만, 현재 SASL 구현 stub 때문에 실제 인증에는 사용되지 않습니다. | `KAFKA_PASSWORD=secret ./detectbot --kafka-password-env KAFKA_PASSWORD` | 비밀번호를 CLI 인자나 설정 파일에 직접 쓰지 않기 위한 형태입니다. |
| `--kafka-mask-sensitive` | Kafka 이벤트의 민감 경로 정보를 마스킹합니다. | finding path에서 파일명만 남기고 앞 경로를 `[MASKED]`로 바꿔 전송합니다. | `--kafka-mask-sensitive` | 기본값은 `false`입니다. 외부 SIEM/파이프라인 전송 시 권장됩니다. |

## 설정 파일

`--config`로 YAML 또는 JSON 설정 파일을 읽을 수 있습니다.

지원 확장자:

- `.yaml`
- `.yml`
- `.json`

CLI에서 명시한 값이 설정 파일보다 우선합니다.

호환 alias도 지원합니다.

- `watch_dir` -> `watch_dirs`
- `content_ext` -> `content_exts`
- `pii_ext` -> `pii_exts`
- `output` -> `out`

### YAML 예시

```yaml
server_type: nginx
nginx_dump: "-"
scan: true
out: /tmp/report.json

watch_dirs:
  - /var/www/html

exclude:
  - /var/cache

max_depth: 12
max_size_mb: 100
newer_than_h: 24
workers: 4
hash: false
follow_symlink: false

allow_mime_prefix:
  - text/html
  - application/json
  - image/

allow_ext:
  - .html
  - .css
  - .js
  - .json
  - .png

content_scan: true
content_max_bytes: 65536
content_max_size_kb: 1024
content_exts:
  - .yaml
  - .yml
  - .json
  - .env

pii_scan: true
pii_max_bytes: 65536
pii_max_size_kb: 256
pii_max_matches: 5
pii_mask: true
pii_store_sample: true
pii_context_keywords: true
pii_exts:
  - .txt
  - .json

kafka:
  enabled: false
  brokers:
    - broker1:9092
  topic: dmz.scan.findings
  client_id: detectbot
  tls: false
  sasl_enabled: false
  username: ""
  password_env: ""
  mask_sensitive: true
```

## 출력 형식

리포트는 pretty JSON으로 저장됩니다.

최상위 필드:

- `report_version`
- `generated_at`
- `scan_started_at`
- `host`
- `inputs`
- `config`
- `active_rules`
- `roots`
- `findings`
- `stats`

### `host` 예시

```json
{
  "hostname": "web-dmz-01",
  "ip_addresses": ["10.10.10.25"],
  "primary_ip": "10.10.10.25",
  "os_type": "linux",
  "os_name": "Rocky Linux",
  "os_version": "8.10",
  "platform": "linux/amd64",
  "collected_at": "2026-03-31T10:00:00+09:00"
}
```

### `roots` 예시

```json
[
  {
    "path": "/var/www/html",
    "real_path": "/srv/www/html",
    "source": "nginx.root",
    "context_hint": "/etc/nginx/nginx.conf:42 | server_name=example.com"
  }
]
```

### `finding` 예시

```json
{
  "path": "/var/www/html/.env",
  "real_path": "/srv/www/html/.env",
  "size_bytes": 4096,
  "mod_time": "2026-03-31T09:30:00+09:00",
  "perm": "-rw-r--r--",
  "ext": ".env",
  "mime_sniff": "text/plain; charset=utf-8",
  "reasons": [
    "ext_not_in_allowlist",
    "credential_password"
  ],
  "severity": "critical",
  "matched_patterns": [
    "credential_password"
  ],
  "evidence_masked": [
    "password=***"
  ],
  "content_flags": "truncated",
  "root_matched": "/var/www/html",
  "root_source": "manual",
  "url_exposure_heuristic": "potentially_web_reachable"
}
```

## Kafka 전송

Kafka를 켜면 전체 리포트가 아니라 요약 이벤트가 전송됩니다.

현재 이벤트에는 아래 정보가 포함됩니다.

- `host`
- `generated_at`
- `roots_count`
- `findings[].path`
- `findings[].severity`
- `findings[].reasons`

`--kafka-mask-sensitive`가 켜져 있으면 Kafka 이벤트의 경로는 파일명만 남기고 마스킹됩니다.

## 실행 시 로그

실행 중 콘솔에는 stderr로 진행 로그가 출력됩니다.

예:

```text
Version: v1.1.3
[INFO] Scan started at: 2026-03-31T10:00:00+09:00
[INFO] Host: web-dmz-01 (10.10.10.25, linux)
[INFO] Mode: nginx-dump + scan
[INFO] Output file: /tmp/report.json
[INFO] Targets discovered: 3
[INFO] Starting filesystem scan...
[INFO] Scanning root: /var/www/html
[INFO] Scan completed at: 2026-03-31T10:00:08+09:00
[INFO] Duration: 8s
[INFO] Scan roots: 3
[INFO] Findings: 7
[SUMMARY] roots=3 files_scanned=812 findings=7 high_risk=1 large_files=2 allowlist_violations=4
[INFO] Report written to: /tmp/report.json
```

`--out -`를 사용하면 JSON은 stdout으로, 로그는 stderr로 분리됩니다.

## 보조 UI

이 저장소에는 보조 UI도 포함되어 있습니다.

- `streamlit_app/`: 옵션 생성과 리포트 해석용 Streamlit UI
- `detectbot_portal/`: 리포트 업로드/조회 중심 포털 UI

CLI 엔트리포인트 실행 파일은 `cmd/detectbot`입니다.

## 검증 명령

```bash
go test ./...
go vet ./...
go build ./cmd/detectbot
```

The Detect Bot logo is based on the Go gopher, originally designed by Renée French.
The original design is licensed under the Creative Commons Attribution 4.0 International License (CC BY 4.0).
Source: https://go.dev/wiki/Gopher
Changes were made for this project.
