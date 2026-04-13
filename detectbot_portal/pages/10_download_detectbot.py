from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

from auth.rbac import ROLE_ADMIN
from auth.session import require_login
from bootstrap import bootstrap_portal
from config.settings import load_settings
from lib.navigation import render_portal_sidebar
from lib.ui import render_portal_header


DIST_DIR = Path(__file__).resolve().parents[1] / "dist"
MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024
ALLOWED_FILENAMES = {
    "detectbot",
    "detectbot.exe",
    "detectbot-linux",
    "detectbot-linux-amd64",
    "detectbot-windows-amd64.exe",
    "detectbot-darwin-amd64",
    "detectbot-darwin-arm64",
}
VERSIONED_FILENAME_PATTERN = re.compile(
    r"^detectbot_(linux_amd64|windows_amd64|darwin_amd64|darwin_arm64)_v\d+(?:_\d+)*(?:\.exe)?$"
)


st.set_page_config(page_title="DetectBot Portal - DetectBot Download", page_icon="DL", layout="wide")

settings = load_settings()
bootstrap_portal(seed_demo_data=False)
current_user = require_login()
render_portal_sidebar(settings, current_user)
is_admin = current_user.get("role") == ROLE_ADMIN


def format_size(size_bytes: int) -> str:
    return f"{size_bytes / 1024 / 1024:.2f} MB"


def format_mtime(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")


def is_allowed_filename(file_name: str) -> bool:
    return file_name in ALLOWED_FILENAMES or bool(VERSIONED_FILENAME_PATTERN.fullmatch(file_name))


def is_dist_child(path: Path) -> bool:
    try:
        resolved_dist = DIST_DIR.resolve()
        resolved_path = path.resolve()
        return resolved_path == resolved_dist or resolved_dist in resolved_path.parents
    except OSError:
        return False


def find_downloadable_files() -> list[Path]:
    if not DIST_DIR.is_dir():
        return []

    files: list[Path] = []
    for candidate in sorted(DIST_DIR.iterdir(), key=lambda item: item.name.lower()):
        if not candidate.is_file():
            continue
        if not is_allowed_filename(candidate.name):
            continue
        if candidate.is_symlink() and not is_dist_child(candidate):
            continue
        if not is_dist_child(candidate):
            continue
        try:
            if candidate.stat().st_size > MAX_DOWNLOAD_BYTES:
                continue
        except OSError:
            continue
        files.append(candidate)
    return files


render_portal_header(
    "DetectBot Download",
    "DetectBot 실행 프로그램을 다운로드합니다.",
)

if is_admin:
    st.caption(f"배포 디렉토리: `{DIST_DIR}`")
else:
    st.caption("다운로드 가능한 DetectBot 실행 파일을 확인할 수 있습니다.")

downloadable_files = find_downloadable_files()
if not downloadable_files:
    st.info("다운로드 가능한 detectbot 실행 파일이 없습니다.")
    st.stop()

rows = []
for file_path in downloadable_files:
    try:
        stat = file_path.stat()
    except OSError:
        continue
    rows.append(
        {
            "파일명": file_path.name,
            "크기": format_size(stat.st_size),
            "수정 시각": format_mtime(file_path),
        }
    )

st.markdown("### 다운로드 파일 목록")
st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)

st.markdown("### 다운로드")
for file_path in downloadable_files:
    try:
        file_bytes = file_path.read_bytes()
    except OSError:
        st.error(f"`{file_path.name}` 파일을 읽을 수 없습니다.")
        continue

    st.download_button(
        label=f"{file_path.name} 다운로드",
        data=file_bytes,
        file_name=file_path.name,
        mime="application/octet-stream",
        key=f"download_{file_path.name}",
        width="stretch",
    )
