# DetectBot Portal Docker Guide

This guide runs the `detectbot_portal` Streamlit app with Docker Compose.

## Prerequisites

- Docker Desktop or Docker Engine with the Compose plugin
- Run commands from the repository root

## Files

- `Dockerfile` builds the Streamlit app image.
- `docker-compose.yml` runs the portal on port `8501`.
- `.dockerignore` keeps local data, secrets, and build noise out of the image.
- `.env.example` lists environment variables you can copy into `.env`.

## Quick Start With SQLite

PowerShell:

```powershell
Copy-Item .env.example .env
docker compose up --build
```

Open:

```text
http://localhost:8501
```

The default SQLite configuration uses these container paths:

```text
DETECTBOT_CONFIG_FILE=/app/detectbot_portal/config/settings.docker.yaml
DETECTBOT_SQLITE_PATH=/app/detectbot_portal/data/detectbot_portal.sqlite3
DETECTBOT_REPORTS_DIR=/app/detectbot_portal/data/reports
```

Docker Compose stores both paths in the named volume:

```text
detectbot_portal_data
```

The data remains available after container restart or recreation. Remove it only when you intentionally want to reset local portal data:

```powershell
docker compose down -v
```

## Run Without Creating `.env`

The compose file has safe SQLite defaults, so this also works:

```powershell
docker compose up --build
```

Create `.env` when you want to set admin credentials, upload size, encryption keys, or PostgreSQL values.

## PostgreSQL Mode

Edit `.env`:

```env
DETECTBOT_DATABASE_BACKEND=postgresql
DETECTBOT_POSTGRES_HOST=postgres
DETECTBOT_POSTGRES_PORT=5432
DETECTBOT_POSTGRES_DB=detectbot_portal
DETECTBOT_POSTGRES_USER=detectbot
DETECTBOT_POSTGRES_PASSWORD=change-me
```

Then run:

```powershell
docker compose --profile postgres up --build
```

PostgreSQL data is stored in the named volume:

```text
detectbot_postgres_data
```

Report uploads still use:

```text
detectbot_portal_data
```

## Streamlit Config

The repository root `.streamlit/config.toml` is copied into the image as:

```text
/app/.streamlit/config.toml
```

Local Streamlit secrets are intentionally excluded:

```text
.streamlit/secrets.toml
```

Use `.env` or your deployment platform's secret manager for sensitive values.

## Download Binaries

The portal download page reads files from:

```text
detectbot_portal/dist
```

That directory is kept in the Docker image so the UI can offer DetectBot binaries for download.

## Important Environment Variables

| Variable | Purpose |
| --- | --- |
| `TZ` | Container timezone, defaults to `Asia/Seoul`. |
| `DETECTBOT_DATABASE_BACKEND` | `sqlite` or `postgresql`. |
| `DETECTBOT_SQLITE_PATH` | SQLite database path inside the container. |
| `DETECTBOT_REPORTS_DIR` | Uploaded report storage path inside the container. |
| `DETECTBOT_AUTO_SEED_DEMO_DATA` | Enables or disables demo data seeding. |
| `DETECTBOT_MAX_UPLOAD_SIZE_MB` | App-level upload size setting. |
| `DETECTBOT_SETTINGS_ENCRYPTION_KEY` | Stable Fernet key for encrypted settings values. |
| `DETECTBOT_ADMIN_USERNAME` | Optional initial admin username. |
| `DETECTBOT_ADMIN_PASSWORD` | Optional initial admin password. |
| `DETECTBOT_POSTGRES_*` | PostgreSQL connection and pool settings. |

`DETECTBOT_SETTINGS_ENCRYPTION_KEY` must remain stable after encrypted settings are saved. If it changes, previously encrypted values may not decrypt.

The Docker compose file uses `detectbot_portal/config/settings.docker.yaml` by default. This file avoids baking a local encrypted PostgreSQL password into the image; PostgreSQL credentials should come from environment variables instead.

## Upload Size Notes

Streamlit also has a server-level upload limit in `.streamlit/config.toml`:

```toml
[server]
maxUploadSize = 10
```

Keep it aligned with:

```env
DETECTBOT_MAX_UPLOAD_SIZE_MB=10
```

Changing the Streamlit server-level value requires restarting the container.

## Useful Commands

Validate Compose configuration:

```powershell
docker compose config
```

Build the image:

```powershell
docker compose build
```

Start in the background:

```powershell
docker compose up --build -d
```

View logs:

```powershell
docker compose logs -f detectbot_portal
```

Stop containers:

```powershell
docker compose down
```

## Troubleshooting

If the app cannot write the database or reports, check that the `detectbot_portal_data` volume is mounted:

```powershell
docker compose config
```

If PostgreSQL mode cannot connect, confirm that you used the profile:

```powershell
docker compose --profile postgres up --build
```

If uploads are rejected, check both `DETECTBOT_MAX_UPLOAD_SIZE_MB` and `.streamlit/config.toml`, then restart the container.
