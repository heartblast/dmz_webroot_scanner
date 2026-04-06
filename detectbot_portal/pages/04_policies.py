import streamlit as st

from config.settings import load_settings
from lib.navigation import render_portal_sidebar
from lib.db import init_db
from lib.models import POLICY_MODES
from lib.repository import get_policy, list_policies, save_policy
from lib.seed import bootstrap_demo_data
from lib.ui import dataframe_or_info, format_timestamp_columns, lines_to_list, render_portal_header


st.set_page_config(
    page_title="DetectBot Portal - 정책 / 옵션 관리",
    page_icon="🛰️",
    layout="wide",
)
init_db()
bootstrap_demo_data()
settings = load_settings()
render_portal_sidebar(settings)

render_portal_header(
    "정책 / 옵션 관리",
    "스캐너 옵션, allowlist, exclude 경로를 정책 단위로 저장하고 관리합니다.",
)

policies_df = format_timestamp_columns(list_policies(active_only=False), ["updated_at"])
st.markdown("### 정책 목록")
dataframe_or_info(policies_df, "등록된 정책이 없습니다.")

left, right = st.columns((1, 1))

with left:
    st.markdown("### 정책 상세")
    if policies_df is not None and not policies_df.empty:
        selected_policy_id = st.selectbox(
            "상세 정책 선택",
            options=policies_df["id"].tolist(),
            format_func=lambda value: (
                f"{policies_df.loc[policies_df['id'] == value, 'policy_name'].iloc[0]}"
            ),
        )
        st.json(get_policy(selected_policy_id), expanded=False)
    else:
        st.info("상세 조회할 정책이 없습니다.")

with right:
    st.markdown("### 정책 등록 / 수정")
    edit_mode = st.radio(
        "작업",
        ["신규 등록", "기존 수정"],
        horizontal=True,
        key="policy_mode_radio",
    )
    editing_policy = None
    if edit_mode == "기존 수정" and policies_df is not None and not policies_df.empty:
        edit_policy_id = st.selectbox(
            "수정 대상 정책",
            options=policies_df["id"].tolist(),
            format_func=lambda value: (
                f"{policies_df.loc[policies_df['id'] == value, 'policy_name'].iloc[0]}"
            ),
            key="policy_edit_id",
        )
        editing_policy = get_policy(edit_policy_id)

    with st.form("policy_form"):
        policy_name = st.text_input(
            "정책명",
            value=(editing_policy or {}).get("policy_name", ""),
        )
        description = st.text_area(
            "정책 설명",
            value=(editing_policy or {}).get("description", ""),
            height=80,
        )
        mode_col, version_col = st.columns(2)
        with mode_col:
            policy_mode = st.selectbox(
                "정책 모드",
                POLICY_MODES,
                index=POLICY_MODES.index(
                    (editing_policy or {}).get("policy_mode", "balanced")
                ),
            )
        with version_col:
            policy_version = st.text_input(
                "정책 버전",
                value=(editing_policy or {}).get("policy_version", "v1"),
            )

        allow_mime = st.text_area(
            "허용 MIME 목록",
            value="\n".join((editing_policy or {}).get("allow_mime", [])),
            height=120,
        )
        allow_ext = st.text_area(
            "허용 확장자 목록",
            value="\n".join((editing_policy or {}).get("allow_ext", [])),
            height=120,
        )
        exclude_paths = st.text_area(
            "제외 경로 목록",
            value="\n".join((editing_policy or {}).get("exclude_paths", [])),
            height=120,
        )

        opt1, opt2, opt3 = st.columns(3)
        with opt1:
            max_depth = st.number_input(
                "max-depth",
                min_value=1,
                value=int((editing_policy or {}).get("max_depth", 10)),
            )
        with opt2:
            newer_than_hours = st.number_input(
                "newer-than-h",
                min_value=0,
                value=int((editing_policy or {}).get("newer_than_hours", 0)),
            )
        with opt3:
            size_threshold_mb = st.number_input(
                "size threshold (MB)",
                min_value=1,
                value=int((editing_policy or {}).get("size_threshold_mb", 100)),
            )

        bool1, bool2, bool3 = st.columns(3)
        with bool1:
            compute_hash = st.checkbox(
                "hash 사용",
                value=bool((editing_policy or {}).get("compute_hash", False)),
            )
        with bool2:
            content_scan_enabled = st.checkbox(
                "content scan 사용",
                value=bool((editing_policy or {}).get("content_scan_enabled", True)),
            )
        with bool3:
            pii_scan_enabled = st.checkbox(
                "PII scan 사용",
                value=bool((editing_policy or {}).get("pii_scan_enabled", True)),
            )

        content_max_kb = st.number_input(
            "content scan 최대 KB",
            min_value=1,
            value=int((editing_policy or {}).get("content_max_kb", 1024)),
        )
        custom_config_json = st.text_area(
            "추가 사용자 정의 설정(JSON 텍스트)",
            value=(editing_policy or {}).get("custom_config_json", ""),
            height=120,
        )
        is_active = st.checkbox(
            "활성 정책",
            value=bool((editing_policy or {}).get("is_active", True)),
        )

        submitted = st.form_submit_button("정책 저장")
        if submitted:
            if not policy_name.strip():
                st.error("정책명은 필수입니다.")
            else:
                policy_id = save_policy(
                    {
                        "id": (editing_policy or {}).get("id"),
                        "policy_name": policy_name,
                        "description": description,
                        "policy_mode": policy_mode,
                        "policy_version": policy_version,
                        "allow_mime": lines_to_list(allow_mime),
                        "allow_ext": lines_to_list(allow_ext),
                        "exclude_paths": lines_to_list(exclude_paths),
                        "max_depth": max_depth,
                        "newer_than_hours": newer_than_hours,
                        "size_threshold_mb": size_threshold_mb,
                        "compute_hash": compute_hash,
                        "content_scan_enabled": content_scan_enabled,
                        "content_max_kb": content_max_kb,
                        "pii_scan_enabled": pii_scan_enabled,
                        "custom_config_json": custom_config_json,
                        "is_active": is_active,
                    }
                )
                st.success(f"정책이 저장되었습니다. ID: {policy_id}")
                st.rerun()
