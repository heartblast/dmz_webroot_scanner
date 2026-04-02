import pandas as pd
import streamlit as st

from bootstrap import bootstrap_portal
from config.settings import load_settings
from lib.models import CRITICALITIES, ENVIRONMENTS, OS_TYPES, WEB_SERVER_TYPES, ZONES
from lib.ui import (
    build_scan_run_display_df,
    build_server_inventory_display_df,
    format_timestamp_columns,
    inject_portal_css,
    render_portal_header,
)
from services.scan_service import ScanService
from services.server_service import ServerService


st.set_page_config(page_title="DetectBot Portal - Server Inventory", page_icon="SV", layout="wide")

bootstrap_portal(seed_demo_data=load_settings().auto_seed_demo_data)
inject_portal_css()

server_service = ServerService()
scan_service = ScanService()


def reset_filters():
    st.session_state["inventory_keyword"] = ""
    st.session_state["inventory_environment"] = "all"
    st.session_state["inventory_zone"] = "all"
    st.session_state["inventory_selected_server_id"] = ""


def load_servers_df():
    environment = "" if st.session_state.get("inventory_environment", "all") == "all" else st.session_state["inventory_environment"]
    zone = "" if st.session_state.get("inventory_zone", "all") == "all" else st.session_state["inventory_zone"]
    return format_timestamp_columns(
        server_service.list_servers_df(
            keyword=st.session_state.get("inventory_keyword", ""),
            environment=environment,
            zone=zone,
            active_only=False,
        ),
        ["created_at", "updated_at"],
    )


def selected_server(servers_df: pd.DataFrame):
    selected_id = st.session_state.get("inventory_selected_server_id", "")
    if selected_id:
        return server_service.get_server(selected_id)
    if servers_df is None or servers_df.empty:
        return None
    selected_id = str(servers_df.iloc[0]["id"])
    st.session_state["inventory_selected_server_id"] = selected_id
    return server_service.get_server(selected_id)


render_portal_header(
    "Server Inventory",
    "ServerService를 통해 서버 CRUD와 최근 스캔 이력을 관리합니다.",
)

for key, value in {
    "inventory_keyword": "",
    "inventory_environment": "all",
    "inventory_zone": "all",
    "inventory_selected_server_id": "",
}.items():
    st.session_state.setdefault(key, value)

filter_cols = st.columns((1.8, 1, 1, 0.8))
with filter_cols[0]:
    st.text_input("Search", key="inventory_keyword", placeholder="server name, hostname, IP, service")
with filter_cols[1]:
    st.selectbox("Environment", options=["all"] + ENVIRONMENTS, key="inventory_environment")
with filter_cols[2]:
    st.selectbox("Zone", options=["all"] + ZONES, key="inventory_zone")
with filter_cols[3]:
    if st.button("Reset Filters", width="stretch"):
        reset_filters()
        st.rerun()

servers_df = load_servers_df()
selected = selected_server(servers_df)
recent_runs_df = pd.DataFrame()
if selected:
    recent_runs_df = format_timestamp_columns(
        scan_service.list_scan_runs_df(server_id=selected["id"], limit=5),
        ["scan_started_at", "generated_at"],
    )

tab_list, tab_detail, tab_create, tab_edit = st.tabs(["Inventory", "Detail", "Create", "Edit/Delete"])

with tab_list:
    st.markdown("### Inventory")
    display_df = build_server_inventory_display_df(servers_df)
    if display_df is None or display_df.empty:
        st.info("No servers found.")
    else:
        selection = st.dataframe(
            display_df,
            width="stretch",
            hide_index=True,
            on_select="rerun",
            selection_mode="single-row",
        )
        selected_rows = []
        try:
            selected_rows = selection.selection.rows
        except Exception:
            selected_rows = []
        if selected_rows:
            st.session_state["inventory_selected_server_id"] = str(servers_df.iloc[selected_rows[0]]["id"])

with tab_detail:
    st.markdown("### Selected Server")
    if not selected:
        st.info("Select a server first.")
    else:
        st.json(selected, expanded=False)
        st.markdown("### Recent Scan Runs")
        if recent_runs_df is None or recent_runs_df.empty:
            st.info("No scan history for this server.")
        else:
            st.dataframe(build_scan_run_display_df(recent_runs_df), width="stretch", hide_index=True)
            if st.button("Open Scan Results", width="stretch"):
                st.session_state["scan_results_focus_server_id"] = selected["id"]
                st.switch_page("pages/02_scan_results.py")


def render_server_form(editing_server=None, form_key="server_form"):
    with st.form(form_key):
        server_name = st.text_input("Server Name", value=(editing_server or {}).get("server_name", ""))
        hostname = st.text_input("Hostname", value=(editing_server or {}).get("hostname", ""))
        ip_address = st.text_input("IP Address", value=(editing_server or {}).get("ip_address", ""))
        service_name = st.text_input("Service Name", value=(editing_server or {}).get("service_name", ""))
        owner_name = st.text_input("Owner", value=(editing_server or {}).get("owner_name", ""))
        environment = st.selectbox(
            "Environment",
            ENVIRONMENTS,
            index=ENVIRONMENTS.index((editing_server or {}).get("environment", "unknown")),
        )
        zone = st.selectbox(
            "Zone",
            ZONES,
            index=ZONES.index((editing_server or {}).get("zone", "unknown")),
        )
        os_type = st.selectbox(
            "OS Type",
            OS_TYPES,
            index=OS_TYPES.index((editing_server or {}).get("os_type", "unknown")),
        )
        os_name = st.text_input("OS Name", value=(editing_server or {}).get("os_name", ""))
        os_version = st.text_input("OS Version", value=(editing_server or {}).get("os_version", ""))
        platform = st.text_input("Platform", value=(editing_server or {}).get("platform", ""))
        web_server_type = st.selectbox(
            "Web Server",
            WEB_SERVER_TYPES,
            index=WEB_SERVER_TYPES.index((editing_server or {}).get("web_server_type", "unknown")),
        )
        criticality = st.selectbox(
            "Criticality",
            CRITICALITIES,
            index=CRITICALITIES.index((editing_server or {}).get("criticality", "medium")),
        )
        upload_enabled = st.checkbox("Upload Enabled", value=bool((editing_server or {}).get("upload_enabled", True)))
        is_active = st.checkbox("Active", value=bool((editing_server or {}).get("is_active", True)))
        notes = st.text_area("Notes", value=(editing_server or {}).get("notes", ""), height=100)
        submitted = st.form_submit_button("Save Server", width="stretch")
        if submitted:
            if not server_name.strip():
                st.error("Server name is required.")
                return
            server_id = server_service.save_server(
                {
                    "id": (editing_server or {}).get("id"),
                    "server_name": server_name,
                    "hostname": hostname,
                    "ip_address": ip_address,
                    "environment": environment,
                    "zone": zone,
                    "os_type": os_type,
                    "os_name": os_name,
                    "os_version": os_version,
                    "platform": platform,
                    "web_server_type": web_server_type,
                    "service_name": service_name,
                    "criticality": criticality,
                    "owner_name": owner_name,
                    "upload_enabled": upload_enabled,
                    "is_active": is_active,
                    "notes": notes,
                }
            )
            st.session_state["inventory_selected_server_id"] = server_id
            st.success(f"Saved server: {server_id}")
            st.rerun()


with tab_create:
    st.markdown("### Create Server")
    render_server_form()

with tab_edit:
    st.markdown("### Edit or Delete")
    if not selected:
        st.info("Select a server first.")
    else:
        render_server_form(editing_server=selected, form_key="edit_server_form")
        if st.button("Delete Selected Server", type="secondary", width="stretch"):
            server_service.delete_server(selected["id"])
            st.session_state["inventory_selected_server_id"] = ""
            st.success("Server deleted.")
            st.rerun()
