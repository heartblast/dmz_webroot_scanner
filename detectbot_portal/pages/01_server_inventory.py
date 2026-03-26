import pandas as pd
import streamlit as st

from lib.db import init_db
from lib.models import CRITICALITIES, ENVIRONMENTS, OS_TYPES, WEB_SERVER_TYPES, ZONES
from lib.repository import get_server, list_servers, save_server
from lib.seed import bootstrap_demo_data
from lib.ui import (
    build_server_inventory_display_df,
    dataframe_or_info,
    format_timestamp_columns,
    inject_portal_css,
    render_metric_summary,
    render_portal_header,
    render_selected_server_banner,
    render_selected_server_focus_card,
    render_server_identity,
    render_server_overview,
    render_server_selection_cards,
    style_server_inventory_table,
)


ALL_OPTION = "전체"
ACTIVE_LABEL = "운영중"
INACTIVE_LABEL = "비활성"
UPLOAD_ON_LABEL = "가능"
UPLOAD_OFF_LABEL = "제한"


st.set_page_config(
    page_title="DetectBot Portal - 서버 인벤토리",
    page_icon="🖥️",
    layout="wide",
)
init_db()
bootstrap_demo_data()
inject_portal_css()


def reset_inventory_filters():
    defaults = {
        "inventory_keyword": "",
        "inventory_environment": ALL_OPTION,
        "inventory_zone": ALL_OPTION,
        "inventory_criticality": ALL_OPTION,
        "inventory_active_status": ALL_OPTION,
        "inventory_upload_status": ALL_OPTION,
        "inventory_selected_server_id": None,
        "inventory_server_picker_id": "",
    }
    for key, value in defaults.items():
        st.session_state[key] = value


def ensure_selected_server_id(current_ids):
    selected_server_id = st.session_state.get("inventory_selected_server_id")
    if selected_server_id in current_ids:
        return selected_server_id

    picker_server_id = st.session_state.get("inventory_server_picker_id")
    if picker_server_id in current_ids:
        st.session_state["inventory_selected_server_id"] = picker_server_id
        return picker_server_id

    selected_server_id = current_ids[0] if current_ids else None
    st.session_state["inventory_selected_server_id"] = selected_server_id
    return selected_server_id


def sync_selected_server_from_picker():
    picker_server_id = st.session_state.get("inventory_server_picker_id")
    if picker_server_id:
        st.session_state["inventory_selected_server_id"] = picker_server_id


def filter_servers(df):
    filtered = df.copy()

    active_status = st.session_state.get("inventory_active_status", ALL_OPTION)
    if active_status == ACTIVE_LABEL:
        filtered = filtered[filtered["is_active"] == True]
    elif active_status == INACTIVE_LABEL:
        filtered = filtered[filtered["is_active"] == False]

    upload_status = st.session_state.get("inventory_upload_status", ALL_OPTION)
    if upload_status == UPLOAD_ON_LABEL:
        filtered = filtered[filtered["upload_enabled"] == True]
    elif upload_status == UPLOAD_OFF_LABEL:
        filtered = filtered[filtered["upload_enabled"] == False]

    criticality = st.session_state.get("inventory_criticality", ALL_OPTION)
    if criticality != ALL_OPTION:
        filtered = filtered[filtered["criticality"] == criticality]

    return filtered.reset_index(drop=True)


def sort_servers_for_operations(df):
    if df is None or df.empty:
        return df

    criticality_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    environment_rank = {"prod": 0, "dr": 1, "uat": 2, "dev": 3, "test": 4, "unknown": 5}
    zone_rank = {"dmz": 0, "internal": 1, "cloud": 2, "partner": 3, "unknown": 4}

    ranked = df.copy()
    ranked["_active_rank"] = ranked["is_active"].apply(lambda value: 0 if bool(value) else 1)
    ranked["_criticality_rank"] = ranked["criticality"].apply(
        lambda value: criticality_rank.get((value or "low").lower(), 9)
    )
    ranked["_environment_rank"] = ranked["environment"].apply(
        lambda value: environment_rank.get((value or "unknown").lower(), 9)
    )
    ranked["_zone_rank"] = ranked["zone"].apply(
        lambda value: zone_rank.get((value or "unknown").lower(), 9)
    )
    ranked["_server_name"] = ranked["server_name"].fillna("").str.lower()
    ranked["_updated_at"] = pd.to_datetime(ranked["updated_at"], errors="coerce")

    ranked = ranked.sort_values(
        by=[
            "_active_rank",
            "_criticality_rank",
            "_environment_rank",
            "_zone_rank",
            "_updated_at",
            "_server_name",
        ],
        ascending=[True, True, True, True, False, True],
        na_position="last",
    ).reset_index(drop=True)
    return ranked.drop(
        columns=[
            "_active_rank",
            "_criticality_rank",
            "_environment_rank",
            "_zone_rank",
            "_server_name",
            "_updated_at",
        ]
    )


def render_server_form(editing_server=None, form_key="server_form"):
    with st.form(form_key):
        server_name = st.text_input(
            "서버명",
            value=(editing_server or {}).get("server_name", ""),
            placeholder="예: web-dmz-01",
        )
        hostname = st.text_input(
            "Hostname",
            value=(editing_server or {}).get("hostname", ""),
            placeholder="예: web-dmz-01.example.local",
        )
        ip_address = st.text_input(
            "IP 주소",
            value=(editing_server or {}).get("ip_address", ""),
            placeholder="예: 10.10.10.21",
        )
        service_name = st.text_input(
            "서비스명",
            value=(editing_server or {}).get("service_name", ""),
        )
        owner_name = st.text_input(
            "담당자 / 관리부서",
            value=(editing_server or {}).get("owner_name", ""),
        )

        env_col, zone_col = st.columns(2)
        with env_col:
            selected_environment = st.selectbox(
                "운영구분",
                ENVIRONMENTS,
                index=ENVIRONMENTS.index((editing_server or {}).get("environment", "unknown")),
            )
        with zone_col:
            selected_zone = st.selectbox(
                "Zone",
                ZONES,
                index=ZONES.index((editing_server or {}).get("zone", "unknown")),
            )

        os_col, web_col = st.columns(2)
        with os_col:
            os_type = st.selectbox(
                "OS 유형",
                OS_TYPES,
                index=OS_TYPES.index((editing_server or {}).get("os_type", "unknown")),
            )
        with web_col:
            web_server_type = st.selectbox(
                "웹서버 유형",
                WEB_SERVER_TYPES,
                index=WEB_SERVER_TYPES.index(
                    (editing_server or {}).get("web_server_type", "unknown")
                ),
            )

        criticality = st.selectbox(
            "중요도",
            CRITICALITIES,
            index=CRITICALITIES.index((editing_server or {}).get("criticality", "medium")),
        )
        toggle_col1, toggle_col2 = st.columns(2)
        with toggle_col1:
            upload_enabled = st.checkbox(
                "업로드 가능",
                value=bool((editing_server or {}).get("upload_enabled", True)),
            )
        with toggle_col2:
            is_active = st.checkbox(
                "활성 자산",
                value=bool((editing_server or {}).get("is_active", True)),
            )

        notes = st.text_area(
            "메모",
            value=(editing_server or {}).get("notes", ""),
            height=120,
            placeholder="운영 메모, 점검 특이사항, 담당 조직 정보를 적어둘 수 있습니다.",
        )

        submit_label = "서버 등록" if editing_server is None else "수정 내용 저장"
        submitted = st.form_submit_button(submit_label, width="stretch")
        if not submitted:
            return

        if not server_name.strip():
            st.error("서버명은 필수입니다. 운영자가 식별 가능한 이름을 입력해 주세요.")
            return

        server_id = save_server(
            {
                "id": (editing_server or {}).get("id"),
                "server_name": server_name,
                "hostname": hostname,
                "ip_address": ip_address,
                "environment": selected_environment,
                "zone": selected_zone,
                "os_type": os_type,
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
        message = (
            f"신규 서버가 등록되었습니다. ID: {server_id}"
            if editing_server is None
            else f"서버 정보가 수정되었습니다. ID: {server_id}"
        )
        st.success(message)
        st.rerun()


render_portal_header(
    "서버 인벤토리",
    "운영 우선순위가 높은 자산을 먼저 보고, 선택한 서버를 상세와 수정 탭에서 같은 기준으로 이어서 관리합니다.",
)

for key, value in {
    "inventory_keyword": "",
    "inventory_environment": ALL_OPTION,
    "inventory_zone": ALL_OPTION,
    "inventory_criticality": ALL_OPTION,
    "inventory_active_status": ALL_OPTION,
    "inventory_upload_status": ALL_OPTION,
    "inventory_selected_server_id": None,
    "inventory_server_picker_id": "",
}.items():
    st.session_state.setdefault(key, value)

filter_box = st.container(border=True)
with filter_box:
    st.markdown("### 빠른 검색 / 필터")
    row1 = st.columns((1.8, 1, 1, 1, 1, 0.7))
    with row1[0]:
        st.text_input(
            "검색어",
            key="inventory_keyword",
            placeholder="서버명, hostname, IP, 서비스명으로 검색",
        )
    with row1[1]:
        st.selectbox("운영구분", [ALL_OPTION] + ENVIRONMENTS, key="inventory_environment")
    with row1[2]:
        st.selectbox("Zone", [ALL_OPTION] + ZONES, key="inventory_zone")
    with row1[3]:
        st.selectbox("중요도", [ALL_OPTION] + CRITICALITIES, key="inventory_criticality")
    with row1[4]:
        st.selectbox(
            "활성 여부",
            [ALL_OPTION, ACTIVE_LABEL, INACTIVE_LABEL],
            key="inventory_active_status",
        )
    with row1[5]:
        st.selectbox(
            "업로드",
            [ALL_OPTION, UPLOAD_ON_LABEL, UPLOAD_OFF_LABEL],
            key="inventory_upload_status",
        )

    action_col1, action_col2 = st.columns((0.22, 0.78))
    with action_col1:
        if st.button("필터 초기화", width="stretch"):
            reset_inventory_filters()
            st.rerun()
    with action_col2:
        st.caption("운영중, 중요도 높음, PROD, DMZ 순으로 우선 정렬됩니다.")

all_servers_df = format_timestamp_columns(
    list_servers(
        keyword=st.session_state["inventory_keyword"],
        environment=""
        if st.session_state["inventory_environment"] == ALL_OPTION
        else st.session_state["inventory_environment"],
        zone="" if st.session_state["inventory_zone"] == ALL_OPTION else st.session_state["inventory_zone"],
        active_only=False,
    ),
    ["updated_at", "created_at"],
)
servers_df = sort_servers_for_operations(filter_servers(all_servers_df))

render_metric_summary(
    [
        {"label": "검색 결과", "value": len(servers_df)},
        {
            "label": "운영중 서버",
            "value": int(servers_df["is_active"].fillna(False).sum()) if not servers_df.empty else 0,
        },
        {
            "label": "업로드 가능",
            "value": int(servers_df["upload_enabled"].fillna(False).sum()) if not servers_df.empty else 0,
        },
        {
            "label": "고중요 자산",
            "value": int(servers_df["criticality"].isin(["critical", "high"]).sum()) if not servers_df.empty else 0,
        },
    ]
)

selected_server = None
selected_server_id = None

if servers_df.empty:
    st.info("조건에 맞는 서버가 없습니다. 필터를 줄이거나 신규 등록 탭에서 서버를 추가해 주세요.")
else:
    current_ids = servers_df["id"].tolist()
    selected_server_id = ensure_selected_server_id(current_ids)
    st.session_state["inventory_server_picker_id"] = selected_server_id or ""

    next_selected_server_id = render_server_selection_cards(
        servers_df,
        selected_server_id,
    )
    if next_selected_server_id != selected_server_id:
        st.session_state["inventory_selected_server_id"] = next_selected_server_id
        st.rerun()

    with st.expander("카드에 없는 서버 빠르게 찾기", expanded=False):
        st.selectbox(
            "현재 필터 결과에서 선택",
            options=[""] + current_ids,
            key="inventory_server_picker_id",
            format_func=lambda value: (
                "선택 없음"
                if not value
                else f"{servers_df.loc[servers_df['id'] == value, 'server_name'].iloc[0]} / "
                f"{servers_df.loc[servers_df['id'] == value, 'hostname'].iloc[0] or '-'}"
            ),
            on_change=sync_selected_server_from_picker,
        )

    selected_server_id = st.session_state.get("inventory_selected_server_id")
    if selected_server_id:
        selected_server = get_server(selected_server_id)

render_selected_server_banner(selected_server, context_label="현재 선택 서버")

tabs = st.tabs(["목록", "상세", "신규 등록", "수정"])
tab_list, tab_detail, tab_create, tab_edit = tabs

with tab_list:
    st.markdown("### 서버 목록")
    st.caption("운영자가 자산 상태를 한눈에 읽을 수 있도록 상태와 중요도를 강조해 보여줍니다.")
    styled_df = style_server_inventory_table(build_server_inventory_display_df(servers_df))
    dataframe_or_info(styled_df, "표시할 서버가 없습니다.")

with tab_detail:
    st.markdown("### 서버 상세")
    if not selected_server:
        st.info("상세 조회할 서버가 없습니다. 먼저 카드에서 서버를 선택해 주세요.")
    else:
        render_selected_server_focus_card(selected_server, mode="detail")
        render_server_identity(selected_server)
        render_server_overview(selected_server)
        with st.expander("원본 상세 정보 보기", expanded=False):
            st.json(selected_server, expanded=False)

with tab_create:
    st.markdown("### 신규 서버 등록")
    st.caption("신규 자산을 등록합니다. 등록 후에는 자동으로 현재 작업 대상 서버로 선택됩니다.")
    render_server_form(editing_server=None, form_key="create_server_form")

with tab_edit:
    st.markdown("### 기존 서버 수정")
    if not selected_server:
        st.info("수정할 서버가 없습니다. 카드에서 서버를 먼저 선택해 주세요.")
    else:
        render_selected_server_focus_card(selected_server, mode="edit")
        render_server_identity(selected_server)
        render_server_form(editing_server=selected_server, form_key="edit_server_form")
