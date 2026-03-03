# dmz_webroot_scanner

DMZ 구간 웹서버의 **웹서빙 경로(root/alias/DocumentRoot)** 를 웹서버 설정 “덤프 출력”에서 자동 수집하고, 해당 경로를 스캔하여 **용도 부적합 파일(스테이징·반출 징후/웹쉘·스크립트 등)** 을 룰 기반으로 탐지한 뒤 **표준 JSON 보고서**로 산출하는 경량 도구입니다.

> ⚠️ 목적은 **침해 지원이 아닌 통제/탐지/감사**입니다.  
> ⚠️ MIME 판별은 `net/http.DetectContentType`(최대 512B sniff) 기반이라 100% 정확하지 않습니다.

---

## 동작 개요

1. Nginx/Apache 설정 덤프를 입력으로 받아 웹서빙 경로 후보를 추출  
   - Nginx: `nginx -T` 출력에서 `root`, `alias` 파싱  
   - Apache: `apachectl -S` 덤프 내 `DocumentRoot`가 포함된 경우에만 파싱(환경에 따라 제한)
2. (선택) `--watch-dir`로 추가 경로 수동 지정
3. (선택) `--scan` 시 후보 경로를 스캔하여 탐지 룰 적용
4. 결과를 JSON(`--out`)으로 출력

---

## 빌드

```bash
go version
go build -o dmz_webroot_scanner dmz_webroot_scanner.go
````

---

## 권장 실행 예시

### 1) Nginx 덤프 파이프 입력 + 스캔

```bash
nginx -T 2>&1 | ./dmz_webroot_scanner --nginx-dump - --scan --out /tmp/report.json
```

### 2) Apache 덤프 파이프 입력 + 스캔

```bash
apachectl -S 2>&1 | ./dmz_webroot_scanner --apache-dump - --scan --out /tmp/report.json
```

> 참고: Apache의 경우 `apachectl -S` 출력에 `DocumentRoot`가 보이지 않으면 루트가 추출되지 않을 수 있습니다.
> 이 경우 `--watch-dir`로 실제 웹루트/업로드 경로를 직접 지정하는 방식을 권장합니다.

### 3) 덤프 파일을 저장해두고 실행

```bash
./dmz_webroot_scanner \
  --nginx-dump /path/nginx_T.txt \
  --apache-dump /path/apache_S.txt \
  --scan \
  --out /tmp/report.json
```

### 4) 수동 경로 지정(테스트/보강)

```bash
./dmz_webroot_scanner --scan \
  --watch-dir /var/www/html \
  --watch-dir /data/webroot \
  --newer-than-h 24 \
  --max-depth 10 \
  --exclude /var/www/html/cache \
  --out /tmp/report.json
```

---

## 사용법

### 입력/출력

* `--nginx-dump <path|->` : `nginx -T` 출력 파일 경로 또는 `-`(stdin)
* `--apache-dump <path|->` : `apachectl -S` 출력 파일 경로 또는 `-`(stdin)
* `--out <path|->` : JSON 리포트 출력 경로(기본: `report.json`, `-`는 stdout)

### 스캔 제어

* `--scan` : 추출된 웹서빙 경로를 스캔
* `--watch-dir <path>` : 수동 점검 경로 추가(반복 지정 가능)
* `--exclude <path-prefix>` : 제외 경로 prefix(반복 지정 가능)
* `--max-depth <n>` : 디렉터리 재귀 깊이 제한(기본: `12`)
* `--newer-than-h <hours>` : 최근 N시간 이내 수정 파일만 평가(기본: `0`=비활성)

### 파일 처리/부하 옵션

* `--max-size-mb <n>` : MIME sniff/hash를 위해 읽을 최대 파일 크기(MB, 기본: `100`)
* `--hash` : Finding에 대해 SHA-256 계산(파일을 `max-size-mb` 한도 내에서 읽음)
* `--follow-symlink` : 심볼릭 링크 추적(기본: false, DMZ 점검에서는 비권장)

### 정책(Allowlist)

* `--allow-mime-prefix <prefix>` : 허용 MIME prefix(반복 지정 가능)
* `--allow-ext <ext>` : 허용 확장자(반복 지정 가능)

#### 기본 Allowlist(미지정 시 자동 적용)

* MIME prefix 기본값:

  * `text/html`, `text/css`, `application/javascript`, `text/javascript`, `application/json`
  * `image/`, `font/`, `application/font-`
  * `application/xml`(sitemap 등), `text/plain`(robots/security.txt 등)
* 확장자 기본값:

  * `.html .htm .css .js .mjs .json .xml .txt`
  * `.png .jpg .jpeg .gif .webp .svg .ico`
  * `.woff .woff2 .ttf .otf .eot`

---

## 탐지 룰(현재 코드 기준)

파일 1개에 대해 아래 조건 중 하나라도 만족하면 **Finding**으로 기록합니다.

1. `mime_not_in_allowlist`

   * sniff 된 MIME이 `--allow-mime-prefix` 목록과 일치/접두사 매칭되지 않음
2. `ext_not_in_allowlist`

   * 확장자가 `--allow-ext` 목록에 없음(확장자 없는 파일은 이 룰에서는 제외될 수 있음)
3. `high_risk_extension`

   * 고위험 확장자(예: `.zip .tar .gz .7z .rar .sql .csv .xlsx ... .php .jsp .aspx .sh .exe .so` 등)
4. `large_file_in_web_path`

   * 50MB 이상 파일이 웹서빙 경로에 존재
5. `ext_mime_mismatch_image`

   * 이미지 확장자(예: `.png/.jpg/...`)인데 MIME이 `image/`가 아님
6. `ext_mime_mismatch_archive`

   * `.js/.css/.html`인데 MIME이 `application/zip`로 탐지되는 경우(위장/오탐 가능)

---

## 결과 JSON 스키마

출력은 아래 구조를 따릅니다(필드명은 코드와 동일).

```json
{
  "generated_at": "2026-03-03T09:10:00+09:00",
  "host": "hostname",
  "inputs": [
    "nginx-dump:-",
    "apache-dump:/path/apache_S.txt"
  ],
  "roots": [
    {
      "path": "/var/www/html",
      "real_path": "/var/www/html",
      "source": "nginx.root",
      "context_hint": "/etc/nginx/nginx.conf:12 | server_name=example.com"
    }
  ],
  "findings": [
    {
      "path": "/var/www/html/upload/a.zip",
      "real_path": "/var/www/html/upload/a.zip",
      "size_bytes": 104857600,
      "mod_time": "2026-03-03T02:11:22+09:00",
      "perm": "-rw-r--r--",
      "ext": ".zip",
      "mime_sniff": "application/zip",
      "reasons": [
        "ext_not_in_allowlist",
        "high_risk_extension",
        "large_file_in_web_path"
      ],
      "sha256": "optional-if-enabled",
      "url_exposure_heuristic": "potentially_web_reachable",
      "root_matched": "/var/www/html",
      "root_source": "nginx.root"
    }
  ],
  "stats": {
    "roots_count": 1,
    "scanned_files": 12345,
    "findings_count": 7
  }
}
```

---

## 운영 권장 설정(서비스 영향 최소화)

* 기본 권장:

  * `--newer-than-h 24`
  * `--max-depth 8~12`
  * `--exclude` 적극 활용(캐시/빌드 산출물/대형 정적 assets)
* 해시는 필요 시에만:

  * `--hash`는 파일 읽기 부하가 증가할 수 있음
* 심볼릭 링크는 기본 미추적:

  * `--follow-symlink`는 DMZ 점검에서는 우회/확대 스캔 위험이 있어 비권장

---

## 한계/주의

* MIME sniff는 512B 기반 휴리스틱이므로 **오탐/미탐 가능**
* Apache는 `apachectl -S` 출력만으로는 DocumentRoot가 노출되지 않는 경우가 많음
  → 이 경우 `--watch-dir`로 실제 웹서빙 경로를 지정하거나, 향후 고도화(설정 파일 파싱) 필요

---

## 로드맵

* Apache vhost 설정 파일 자동 파싱(Include 확장 포함)
* 정책 외부화(YAML): allowlist/exclude/임계치/리스크 스코어링
* 샘플링 기반 PII 탐지(성능 제한 포함)
* SIEM 연계용 이벤트 스키마(ECS) 변환/전송 옵션 추가

