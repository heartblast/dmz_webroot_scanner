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

## 환경변수 요약

- `DETECTBOT_CONFIG_FILE`
- `DETECTBOT_DATABASE_BACKEND`
- `DETECTBOT_SQLITE_PATH`
- `DETECTBOT_POSTGRES_HOST`
- `DETECTBOT_POSTGRES_PORT`
- `DETECTBOT_POSTGRES_DB`
- `DETECTBOT_POSTGRES_USER`
- `DETECTBOT_POSTGRES_PASSWORD`
- `DETECTBOT_POSTGRES_POOL_PRE_PING`
- `DETECTBOT_POSTGRES_POOL_SIZE`
- `DETECTBOT_POSTGRES_MAX_OVERFLOW`
- `DETECTBOT_REPORTS_DIR`
- `DETECTBOT_AUTO_SEED_DEMO_DATA`
- `DETECTBOT_SETTINGS_ENCRYPTION_KEY`

## 백엔드 전환

YAML의 `database.backend` 또는 환경변수 `DETECTBOT_DATABASE_BACKEND`만 바꾸면 됩니다. Streamlit 페이지는 백엔드와 무관하게 동일한 service 기반 호출 경로를 유지합니다.
