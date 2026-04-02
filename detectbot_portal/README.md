# DetectBot Portal

DetectBot Portal is a Streamlit UI for managing server inventory, scan results, scan policies, and dashboard summaries on top of a shared SQLAlchemy data model.

## Architecture

- `config/settings.py`: backend selection and runtime settings
- `db/*`: SQLAlchemy base, models, engine/session factory, schema bootstrap
- `repositories/*`: database access only
- `services/*`: business logic for Streamlit pages
- `pages/*`: UI layer only, no direct DB connection
- `pages/07_option_generator.py`: Detect Bot option generation UI ported from `streamlit_app`
- `pages/08_scenario_generator.py`: scenario-driven wizard for building scan options

## Supported Backends

- `sqlite` via `sqlite+pysqlite`
- `postgresql` via `postgresql+psycopg`

## Settings UI

- Admin page: `detectbot_portal/pages/06_settings_admin.py`
- The page edits `detectbot_portal/config/settings.yaml`
- PostgreSQL passwords are stored as `password_enc`
- Plain `password` is not written by the settings UI

Encryption key environment variable:

```bash
set DETECTBOT_SETTINGS_ENCRYPTION_KEY=YOUR_FERNET_KEY
```

Example key generation:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

## Configuration

`config/settings.py` reads defaults, then optional YAML, then environment variables.

Example YAML:

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

Set a custom config file:

```bash
set DETECTBOT_CONFIG_FILE=D:\path\to\settings.yaml
```

## SQLite Example

```bash
set DETECTBOT_DATABASE_BACKEND=sqlite
set DETECTBOT_SQLITE_PATH=D:\golang\go-workspace\dmz_webroot_scanner\detectbot_portal\data\detectbot_portal.sqlite3
streamlit run detectbot_portal/app.py
```

SQLite runtime options applied automatically:

- `PRAGMA journal_mode=WAL`
- `PRAGMA foreign_keys=ON`
- `PRAGMA busy_timeout`

## PostgreSQL Example

```bash
set DETECTBOT_DATABASE_BACKEND=postgresql
set DETECTBOT_POSTGRES_HOST=localhost
set DETECTBOT_POSTGRES_PORT=5432
set DETECTBOT_POSTGRES_DB=detectbot_portal
set DETECTBOT_POSTGRES_USER=detectbot
set DETECTBOT_POSTGRES_PASSWORD=detectbot
streamlit run detectbot_portal/app.py
```

PostgreSQL runtime options applied automatically:

- `pool_pre_ping`
- `pool_size`
- `max_overflow`

## Environment Variable Summary

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

## Backend Switching

Change only `database.backend` in YAML or `DETECTBOT_DATABASE_BACKEND` in the environment. The Streamlit pages keep the same service-based call path regardless of backend.
