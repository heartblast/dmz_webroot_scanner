# DetectBot Portal

DetectBot Portal은 공통 SQLAlchemy 데이터 모델 위에서 서버 인벤토리, 스캔 결과, 스캔 정책, 대시보드 요약을 관리하는 Streamlit UI입니다.

## 아키텍처

- `config/settings.py`: 백엔드 선택 및 런타임 설정
- `db/*`: SQLAlchemy base, 모델, engine/session factory, 스키마 초기화
- `repositories/*`: 데이터베이스 접근 전용 계층
- `services/*`: Streamlit 페이지에서 사용하는 비즈니스 로직
- `pages/*`: UI 전용 계층, 직접 DB 연결 없음
- `pages/07_option_generator.py`: `streamlit_app`에서 옮겨온 Detect Bot 옵션 생성 UI
- `pages/08_scenario_generator.py`: 스캔 옵션 구성을 위한 시나리오 기반 wizard

## 지원 백엔드

- `sqlite` via `sqlite+pysqlite`
- `postgresql` via `postgresql+psycopg`

## 설정 UI

- 관리자 페이지: `detectbot_portal/pages/06_settings_admin.py`
- 이 페이지는 `detectbot_portal/config/settings.yaml`을 수정합니다.
- PostgreSQL 비밀번호는 `password_enc` 형태로 저장됩니다.
- 설정 UI는 평문 `password`를 직접 기록하지 않습니다.

암호화 키 환경변수:

```bash
set DETECTBOT_SETTINGS_ENCRYPTION_KEY=YOUR_FERNET_KEY
```

키 생성 예시:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

## 설정 구조

`config/settings.py`는 기본값을 읽고, 그 다음 선택적 YAML 설정을 적용한 뒤, 마지막으로 환경변수를 덮어씁니다.

예시 YAML:

```yaml
database:
  backend: sqlite
  sqlite:
    path: detectbot_portal/data/detectbot_portal.sqlite3
  postgresql:
    host: localhost
    port: 5432
    database: detectbot_portal
    user: detectbot
    password_enc: ""
    pool_pre_ping: true
    pool_size: 5
    max_overflow: 10
app:
  reports_dir: detectbot_portal/data/reports
  auto_seed_demo_data: true
```

사용자 지정 설정 파일 지정:

```bash
set DETECTBOT_CONFIG_FILE=D:\path\to\settings.yaml
```

## SQLite 예시

```bash
set DETECTBOT_DATABASE_BACKEND=sqlite
set DETECTBOT_SQLITE_PATH=D:\golang\go-workspace\dmz_webroot_scanner\detectbot_portal\data\detectbot_portal.sqlite3
streamlit run detectbot_portal/app.py
```

SQLite 실행 시 자동 적용되는 런타임 옵션:

- `PRAGMA journal_mode=WAL`
- `PRAGMA foreign_keys=ON`
- `PRAGMA busy_timeout`

## PostgreSQL 예시

```bash
set DETECTBOT_DATABASE_BACKEND=postgresql
set DETECTBOT_POSTGRES_HOST=localhost
set DETECTBOT_POSTGRES_PORT=5432
set DETECTBOT_POSTGRES_DB=detectbot_portal
set DETECTBOT_POSTGRES_USER=detectbot
set DETECTBOT_POSTGRES_PASSWORD=detectbot
streamlit run detectbot_portal/app.py
```

PostgreSQL 실행 시 자동 적용되는 런타임 옵션:

- `pool_pre_ping`
- `pool_size`
- `max_overflow`

## 환경변수 옵션

| 옵션 | 설명 | 실제 동작 | 사용 예시 | 기본값/주의사항 |
| --- | --- | --- | --- | --- |
| `DETECTBOT_CONFIG_FILE` | 포털 설정 YAML 경로를 바꿉니다. | 지정한 YAML을 기본 설정과 병합한 뒤 환경변수 값으로 다시 덮어씁니다. | `set DETECTBOT_CONFIG_FILE=D:\path\to\settings.yaml` | 기본값은 `detectbot_portal/config/settings.yaml`입니다. |
| `DETECTBOT_DATABASE_BACKEND` | 포털 DB 백엔드를 선택합니다. | `sqlite` 또는 `postgresql` 값을 읽어 SQLAlchemy URL 생성 방식을 바꿉니다. | `set DETECTBOT_DATABASE_BACKEND=postgresql` | 기본값은 `sqlite`입니다. |
| `DETECTBOT_SQLITE_PATH` | SQLite DB 파일 경로를 지정합니다. | SQLite backend일 때 DB 파일 위치로 사용됩니다. 상대 경로면 포털 루트 기준으로 해석됩니다. | `set DETECTBOT_SQLITE_PATH=D:\data\detectbot.sqlite3` | 기본값은 `detectbot_portal/data/detectbot_portal.sqlite3`입니다. |
| `DETECTBOT_POSTGRES_HOST` | PostgreSQL host를 지정합니다. | PostgreSQL SQLAlchemy URL의 host에 반영됩니다. | `set DETECTBOT_POSTGRES_HOST=localhost` | 기본값은 `localhost`입니다. |
| `DETECTBOT_POSTGRES_PORT` | PostgreSQL port를 지정합니다. | 정수로 변환되어 PostgreSQL 연결 URL에 반영됩니다. | `set DETECTBOT_POSTGRES_PORT=5432` | 기본값은 `5432`입니다. |
| `DETECTBOT_POSTGRES_DB` | PostgreSQL database 이름을 지정합니다. | PostgreSQL 연결 URL의 database에 반영됩니다. | `set DETECTBOT_POSTGRES_DB=detectbot_portal` | 기본값은 `detectbot_portal`입니다. |
| `DETECTBOT_POSTGRES_USER` | PostgreSQL 사용자명을 지정합니다. | PostgreSQL 연결 URL의 user에 반영됩니다. | `set DETECTBOT_POSTGRES_USER=detectbot` | 기본값은 `detectbot`입니다. |
| `DETECTBOT_POSTGRES_PASSWORD` | PostgreSQL 비밀번호를 지정합니다. | YAML의 평문/암호화 비밀번호보다 우선해 PostgreSQL 연결 URL에 사용됩니다. | `set DETECTBOT_POSTGRES_PASSWORD=detectbot` | 기본값은 빈 값입니다. 환경변수에 있으면 `password_enc` 복호화 결과보다 우선합니다. |
| `DETECTBOT_POSTGRES_POOL_PRE_PING` | PostgreSQL connection pool pre-ping을 제어합니다. | `1`, `true`, `yes`, `on`이면 true로 처리됩니다. | `set DETECTBOT_POSTGRES_POOL_PRE_PING=true` | 기본값은 `true`입니다. |
| `DETECTBOT_POSTGRES_POOL_SIZE` | PostgreSQL pool size를 지정합니다. | 정수로 변환되어 SQLAlchemy pool 설정에 반영됩니다. | `set DETECTBOT_POSTGRES_POOL_SIZE=10` | 기본값은 `5`입니다. |
| `DETECTBOT_POSTGRES_MAX_OVERFLOW` | PostgreSQL pool overflow 크기를 지정합니다. | 정수로 변환되어 SQLAlchemy pool 설정에 반영됩니다. | `set DETECTBOT_POSTGRES_MAX_OVERFLOW=20` | 기본값은 `10`입니다. |
| `DETECTBOT_REPORTS_DIR` | 업로드/저장 리포트 디렉터리를 지정합니다. | 리포트 파일 저장 위치로 사용됩니다. 상대 경로면 포털 루트 기준으로 해석됩니다. | `set DETECTBOT_REPORTS_DIR=D:\detectbot\reports` | 기본값은 `detectbot_portal/data/reports`입니다. |
| `DETECTBOT_AUTO_SEED_DEMO_DATA` | 데모 데이터 자동 seed 여부를 제어합니다. | `1`, `true`, `yes`, `on`이면 자동 seed를 켠 상태로 설정됩니다. | `set DETECTBOT_AUTO_SEED_DEMO_DATA=false` | 기본값은 `true`입니다. |
| `DETECTBOT_SETTINGS_ENCRYPTION_KEY` | 설정 UI의 비밀번호 암호화/복호화 키를 지정합니다. | Fernet key로 PostgreSQL `password_enc` 값을 암호화하거나 복호화합니다. | `set DETECTBOT_SETTINGS_ENCRYPTION_KEY=<fernet-key>` | 암호화 비밀번호를 쓰려면 유효한 Fernet key가 필요합니다. |
| `DETECTBOT_ADMIN_USERNAME` | 최초 관리자 계정 ID를 지정합니다. | 활성 admin 계정이 없을 때 초기 admin 생성에 사용됩니다. | `set DETECTBOT_ADMIN_USERNAME=admin` | 기존 admin이 있으면 새로 만들지 않습니다. |
| `DETECTBOT_ADMIN_PASSWORD` | 최초 관리자 계정 비밀번호를 지정합니다. | 활성 admin 계정이 없을 때 초기 admin 비밀번호로 사용되며 비밀번호 정책 검증을 거칩니다. | `set DETECTBOT_ADMIN_PASSWORD=ChangeMe123!` | 최초 admin 생성 시 `DETECTBOT_ADMIN_USERNAME`과 함께 필요합니다. |

## 백엔드 전환

YAML의 `database.backend` 또는 환경변수 `DETECTBOT_DATABASE_BACKEND`만 바꾸면 됩니다. Streamlit 페이지는 백엔드와 무관하게 동일한 service 기반 호출 경로를 유지합니다.
