import streamlit as st


def render_portal_sidebar(settings):
    with st.sidebar:
        st.markdown("### DetectBot Portal")
        st.caption(f"backend: `{settings.database.backend}`")
        st.page_link("app.py", label="🏠 Home")
        st.page_link("pages/01_server_inventory.py", label="🖥️ Server Inventory")
        st.page_link("pages/02_report_upload_history.py", label="📥 Report Upload & History")
        st.page_link("pages/03_findings.py", label="🚨 Findings")
        st.page_link("pages/03_scan_policies.py", label="🛡️ Scan Policies")
        st.page_link("pages/04_dashboard.py", label="📊 Dashboard")
        st.page_link("pages/04_policies.py", label="🧩 Policies")
        st.page_link("pages/05_detection_report_viewer.py", label="📄 Report Viewer")
        st.page_link("pages/06_settings_admin.py", label="⚙️ Settings")
        st.page_link("pages/07_option_generator.py", label="🧪 Option Generator")
        st.page_link("pages/08_scenario_generator.py", label="🗺️ Scenario Generator")
