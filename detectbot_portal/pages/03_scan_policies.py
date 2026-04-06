import streamlit as st

from bootstrap import bootstrap_portal
from config.settings import load_settings
from lib.navigation import render_portal_sidebar
from lib.models import POLICY_MODES
from lib.ui import dataframe_or_info, format_timestamp_columns, lines_to_list, render_portal_header
from services.policy_service import PolicyService


st.set_page_config(page_title="DetectBot Portal - Scan Policies", page_icon="PL", layout="wide")

settings = load_settings()
bootstrap_portal(seed_demo_data=settings.auto_seed_demo_data)
render_portal_sidebar(settings)
policy_service = PolicyService()

render_portal_header(
    "Scan Policies",
    "PolicyService를 통해 정책 CRUD를 관리합니다.",
)

policies_df = format_timestamp_columns(policy_service.list_policies_df(active_only=False), ["created_at", "updated_at"])
dataframe_or_info(policies_df, "No policies found.")

left, right = st.columns(2)

with left:
    st.markdown("### Policy Detail")
    if policies_df is not None and not policies_df.empty:
        selected_policy_id = st.selectbox(
            "Select Policy",
            options=policies_df["id"].tolist(),
            format_func=lambda value: policies_df.loc[policies_df["id"] == value, "policy_name"].iloc[0],
        )
        st.json(policy_service.get_policy(selected_policy_id), expanded=False)
    else:
        selected_policy_id = ""
        st.info("Create a policy first.")

with right:
    st.markdown("### Create or Update")
    edit_mode = st.radio("Mode", ["Create", "Edit"], horizontal=True)
    editing_policy = policy_service.get_policy(selected_policy_id) if edit_mode == "Edit" and selected_policy_id else None
    with st.form("policy_form"):
        policy_name = st.text_input("Policy Name", value=(editing_policy or {}).get("policy_name", ""))
        description = st.text_area("Description", value=(editing_policy or {}).get("description", ""), height=80)
        policy_mode = st.selectbox(
            "Policy Mode",
            POLICY_MODES,
            index=POLICY_MODES.index((editing_policy or {}).get("policy_mode", "balanced")),
        )
        policy_version = st.text_input("Policy Version", value=(editing_policy or {}).get("policy_version", "v1"))
        allow_mime = st.text_area("Allow MIME", value="\n".join((editing_policy or {}).get("allow_mime", [])), height=100)
        allow_ext = st.text_area("Allow Extensions", value="\n".join((editing_policy or {}).get("allow_ext", [])), height=100)
        exclude_paths = st.text_area("Exclude Paths", value="\n".join((editing_policy or {}).get("exclude_paths", [])), height=100)
        max_depth = st.number_input("Max Depth", min_value=1, value=int((editing_policy or {}).get("max_depth", 10)))
        newer_than_hours = st.number_input("Newer Than Hours", min_value=0, value=int((editing_policy or {}).get("newer_than_hours", 0)))
        size_threshold_mb = st.number_input("Size Threshold MB", min_value=1, value=int((editing_policy or {}).get("size_threshold_mb", 100)))
        compute_hash = st.checkbox("Compute Hash", value=bool((editing_policy or {}).get("compute_hash", False)))
        content_scan_enabled = st.checkbox("Content Scan Enabled", value=bool((editing_policy or {}).get("content_scan_enabled", True)))
        content_max_kb = st.number_input("Content Max KB", min_value=1, value=int((editing_policy or {}).get("content_max_kb", 1024)))
        pii_scan_enabled = st.checkbox("PII Scan Enabled", value=bool((editing_policy or {}).get("pii_scan_enabled", True)))
        custom_config_json = st.text_area("Custom Config JSON", value=(editing_policy or {}).get("custom_config_json", ""), height=100)
        is_active = st.checkbox("Active", value=bool((editing_policy or {}).get("is_active", True)))
        submitted = st.form_submit_button("Save Policy", width="stretch")
        if submitted:
            if not policy_name.strip():
                st.error("Policy name is required.")
            else:
                policy_id = policy_service.save_policy(
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
                st.success(f"Saved policy: {policy_id}")
                st.rerun()

    if editing_policy and st.button("Delete Policy", type="secondary", width="stretch"):
        policy_service.delete_policy(editing_policy["id"])
        st.success("Policy deleted.")
        st.rerun()
