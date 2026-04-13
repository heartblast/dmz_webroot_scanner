import streamlit as st

from auth.rbac import can_access_page
from auth.session import render_auth_sidebar


def render_portal_sidebar(settings, current_user: dict | None = None):
    role = (current_user or {}).get("role")
    with st.sidebar:
        st.markdown("### DetectBot Portal")
        st.caption(f"backend: `{settings.database.backend}`")
        if can_access_page(role, "home"):
            st.page_link("app.py", label="🏠 Home")
        if can_access_page(role, "server_inventory"):
            st.page_link("pages/01_server_inventory.py", label="🖥️ Server Inventory")
        if can_access_page(role, "report_upload_history"):
            st.page_link("pages/02_report_upload_history.py", label="📥 Report Upload & History")
        if can_access_page(role, "findings"):
            st.page_link("pages/03_findings.py", label="🚨 Findings")
        if can_access_page(role, "scan_policies"):
            st.page_link("pages/03_scan_policies.py", label="🛡️ Scan Policies")
        if can_access_page(role, "dashboard"):
            st.page_link("pages/04_dashboard.py", label="📊 Dashboard")
        if can_access_page(role, "policies"):
            st.page_link("pages/04_policies.py", label="🧩 Policies")
        if can_access_page(role, "report_viewer"):
            st.page_link("pages/05_detection_report_viewer.py", label="📄 Report Viewer")
        if can_access_page(role, "download_detectbot"):
            st.page_link("pages/10_download_detectbot.py", label="⬇️ DetectBot Download")
        if can_access_page(role, "settings"):
            st.page_link("pages/06_settings_admin.py", label="⚙️ Settings")
        if can_access_page(role, "user_management"):
            st.page_link("pages/09_user_management.py", label="👥 User Management")
        if can_access_page(role, "option_generator"):
            st.page_link("pages/07_option_generator.py", label="🧪 Option Generator")
        if can_access_page(role, "scenario_generator"):
            st.page_link("pages/08_scenario_generator.py", label="🗺️ Scenario Generator")
        if current_user is not None:
            render_auth_sidebar(current_user)
