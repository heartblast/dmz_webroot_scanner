"""
UI helpers for DetectBot Portal.
"""

import html
import json

import pandas as pd
import streamlit as st


CRITICALITY_LABELS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}

ENV_BADGES = {
    "prod": ("PROD", "env-prod"),
    "dev": ("DEV", "env-dev"),
    "test": ("TEST", "env-test"),
    "uat": ("UAT", "env-uat"),
    "dr": ("DR", "env-dr"),
    "unknown": ("UNKNOWN", "env-unknown"),
}

ZONE_BADGES = {
    "dmz": ("DMZ", "zone-dmz"),
    "internal": ("INTERNAL", "zone-internal"),
    "cloud": ("CLOUD", "zone-cloud"),
    "partner": ("PARTNER", "zone-partner"),
    "unknown": ("UNKNOWN", "zone-unknown"),
}

INPUT_TYPE_LABELS = {
    "manual_json": "수동 JSON",
    "nginx_dump": "Nginx Dump",
    "apache_dump": "Apache Dump",
    "watch_dir": "Watch Dir",
    "kafka_event": "Kafka Event",
    "unknown": "미분류",
}


def inject_portal_css():
    st.markdown(
        """
        <style>
        .portal-pill {
            display:inline-block;
            padding:0.22rem 0.55rem;
            margin:0 0.28rem 0.28rem 0;
            border-radius:999px;
            font-size:0.78rem;
            font-weight:700;
            line-height:1.2;
            border:1px solid transparent;
        }
        .pill-critical { background:#fee2e2; color:#991b1b; border-color:#fecaca; }
        .pill-high { background:#ffedd5; color:#9a3412; border-color:#fdba74; }
        .pill-medium { background:#fef3c7; color:#92400e; border-color:#fcd34d; }
        .pill-low { background:#dcfce7; color:#166534; border-color:#86efac; }
        .pill-active { background:#dcfce7; color:#166534; border-color:#86efac; }
        .pill-inactive { background:#e5e7eb; color:#374151; border-color:#cbd5e1; }
        .pill-upload-on { background:#dbeafe; color:#1d4ed8; border-color:#93c5fd; }
        .pill-upload-off { background:#e5e7eb; color:#475569; border-color:#cbd5e1; }
        .pill-latest { background:#ecfeff; color:#155e75; border-color:#67e8f9; }
        .pill-history { background:#f8fafc; color:#475569; border-color:#cbd5e1; }
        .pill-findings-high { background:#fee2e2; color:#991b1b; border-color:#fecaca; }
        .pill-findings-medium { background:#ffedd5; color:#9a3412; border-color:#fdba74; }
        .pill-findings-low { background:#dcfce7; color:#166534; border-color:#86efac; }
        .pill-input-type { background:#eff6ff; color:#1d4ed8; border-color:#bfdbfe; }
        .env-prod, .zone-dmz { background:#fee2e2; color:#991b1b; border-color:#fecaca; }
        .env-dev, .env-test, .env-uat, .env-dr,
        .zone-internal, .zone-cloud, .zone-partner, .zone-unknown, .env-unknown {
            background:#eff6ff; color:#1e3a8a; border-color:#bfdbfe;
        }
        .server-card, .run-card {
            border:1px solid #dbe2ea;
            border-radius:16px;
            padding:0.9rem 1rem;
            background:linear-gradient(180deg, #ffffff 0%, #f8fafc 100%);
            box-shadow:0 1px 3px rgba(15, 23, 42, 0.05);
            margin-bottom:0.5rem;
        }
        .server-card { min-height:154px; }
        .run-card { min-height:172px; }
        .server-card.selected, .run-card.selected {
            border:2px solid #0f766e;
            box-shadow:0 0 0 3px rgba(15, 118, 110, 0.10);
            background:linear-gradient(180deg, #f0fdfa 0%, #ffffff 100%);
        }
        .server-card h4, .run-card h4 {
            margin:0 0 0.35rem 0;
            font-size:1rem;
            line-height:1.3;
        }
        .server-card .meta, .run-card .meta {
            color:#475569;
            font-size:0.83rem;
            margin-bottom:0.55rem;
            word-break:break-all;
        }
        .server-card .service, .run-card .service {
            color:#0f172a;
            font-size:0.86rem;
            font-weight:600;
            margin-top:0.45rem;
        }
        .run-card .hint {
            color:#64748b;
            font-size:0.80rem;
            margin-top:0.4rem;
        }
        .info-panel {
            border:1px solid #dbe2ea;
            border-radius:16px;
            padding:1rem 1.1rem;
            background:linear-gradient(180deg, #f8fafc 0%, #ffffff 100%);
            margin-bottom:1rem;
        }
        .info-panel h4 {
            margin:0 0 0.35rem 0;
            font-size:1rem;
        }
        .info-panel p {
            margin:0;
            color:#475569;
            font-size:0.92rem;
            line-height:1.5;
        }
        .selected-server-banner {
            border:1px solid #99f6e4;
            border-radius:18px;
            padding:1rem 1.1rem;
            background:linear-gradient(135deg, #ecfeff 0%, #f0fdfa 100%);
            box-shadow:0 2px 6px rgba(15, 118, 110, 0.08);
            margin:0.75rem 0 1rem 0;
        }
        .selected-server-banner h4,
        .selected-server-focus h4 {
            margin:0 0 0.3rem 0;
            font-size:0.92rem;
            color:#0f766e;
            letter-spacing:0.01em;
        }
        .selected-server-banner h3,
        .selected-server-focus h3 {
            margin:0 0 0.35rem 0;
            font-size:1.15rem;
            line-height:1.3;
            color:#0f172a;
        }
        .selected-server-banner .meta,
        .selected-server-focus .meta {
            color:#475569;
            font-size:0.9rem;
            margin-bottom:0.55rem;
            word-break:break-all;
        }
        .selected-server-banner .hint,
        .selected-server-focus .hint {
            margin-top:0.45rem;
            color:#155e75;
            font-size:0.84rem;
            font-weight:600;
        }
        .selected-server-focus {
            border:1px solid #fecaca;
            border-left:6px solid #dc2626;
            border-radius:18px;
            padding:1rem 1.1rem;
            background:linear-gradient(180deg, #fff7ed 0%, #ffffff 100%);
            box-shadow:0 2px 8px rgba(127, 29, 29, 0.08);
            margin:0.5rem 0 1rem 0;
        }
        .selected-server-empty {
            border:1px dashed #cbd5e1;
            border-radius:16px;
            padding:0.95rem 1rem;
            background:#f8fafc;
            color:#475569;
            margin:0.75rem 0 1rem 0;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_portal_header(title, caption):
    st.title(title)
    st.caption(caption)


def render_metric_cards(metrics):
    col1, col2, col3, col4, col5, col6 = st.columns(6)
    col1.metric("전체 등록 서버", metrics.get("servers_total", 0))
    col2.metric("최근 점검 서버", metrics.get("recent_scanned_servers", 0))
    col3.metric("전체 탐지 건수", metrics.get("findings_total", 0))
    severity = metrics.get("severity_counts", {})
    col4.metric("Critical", severity.get("critical", 0))
    col5.metric("High", severity.get("high", 0))
    col6.metric("Medium / Low", severity.get("medium", 0) + severity.get("low", 0))


def render_metric_summary(metrics):
    if not metrics:
        return
    columns = st.columns(len(metrics))
    for column, metric in zip(columns, metrics):
        column.metric(metric["label"], metric["value"], metric.get("delta"))


def dataframe_or_info(df, message):
    if df is None:
        st.info(message)
        return

    base_df = getattr(df, "data", df)
    if getattr(base_df, "empty", False):
        st.info(message)
        return

    st.dataframe(df, width="stretch", hide_index=True)


def json_text_to_lines(text):
    if not text:
        return ""
    try:
        value = json.loads(text)
        if isinstance(value, list):
            return "\n".join(str(item) for item in value)
        return json.dumps(value, ensure_ascii=False, indent=2)
    except Exception:
        return str(text)


def lines_to_list(text):
    return [line.strip() for line in (text or "").splitlines() if line.strip()]


def format_timestamp_columns(df: pd.DataFrame, columns):
    if df is None or df.empty:
        return df
    formatted = df.copy()
    for column in columns:
        if column in formatted.columns:
            formatted[column] = (
                formatted[column].fillna("").astype(str).str.replace("T", " ", regex=False)
            )
    return formatted


def bool_badge(value, true_label="사용", false_label="미사용"):
    return true_label if bool(value) else false_label


def criticality_badge_text(value):
    return CRITICALITY_LABELS.get((value or "").lower(), str(value or "-").upper())


def env_badge_text(value):
    return ENV_BADGES.get((value or "").lower(), (str(value or "-").upper(), ""))[0]


def zone_badge_text(value):
    return ZONE_BADGES.get((value or "").lower(), (str(value or "-").upper(), ""))[0]


def input_type_badge_text(value):
    return INPUT_TYPE_LABELS.get((value or "").lower(), value or "미분류")


def _pill_html(label, css_class):
    return f"<span class='portal-pill {css_class}'>{html.escape(str(label))}</span>"


def criticality_pill(value):
    level = (value or "").lower()
    css_class = f"pill-{level}" if level in CRITICALITY_LABELS else "pill-low"
    return _pill_html(criticality_badge_text(value), css_class)


def status_pill(is_active):
    return _pill_html("운영중" if is_active else "비활성", "pill-active" if is_active else "pill-inactive")


def upload_pill(upload_enabled):
    return _pill_html("업로드 가능" if upload_enabled else "업로드 제한", "pill-upload-on" if upload_enabled else "pill-upload-off")


def env_pill(value):
    label, css_class = ENV_BADGES.get((value or "").lower(), (str(value or "-").upper(), "env-unknown"))
    return _pill_html(label, css_class)


def zone_pill(value):
    label, css_class = ZONE_BADGES.get((value or "").lower(), (str(value or "-").upper(), "zone-unknown"))
    return _pill_html(label, css_class)


def input_type_pill(value):
    return _pill_html(input_type_badge_text(value), "pill-input-type")


def latest_run_pill(is_latest):
    return _pill_html("최신 실행" if is_latest else "이전 실행", "pill-latest" if is_latest else "pill-history")


def findings_count_pill(count):
    total = int(count or 0)
    if total >= 50:
        css_class = "pill-findings-high"
    elif total >= 10:
        css_class = "pill-findings-medium"
    else:
        css_class = "pill-findings-low"
    return _pill_html(f"탐지 {total}건", css_class)


def render_info_panel(title, body):
    st.markdown(
        f"""
        <div class="info-panel">
            <h4>{html.escape(title)}</h4>
            <p>{html.escape(body)}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _selected_server_markup(server, context_label, hint, css_class):
    return f"""
    <div class="{css_class}">
        <h4>{html.escape(context_label)}</h4>
        <h3>{html.escape(server.get('server_name') or '-')}</h3>
        <div class="meta">{html.escape(server.get('hostname') or '-')} / {html.escape(server.get('ip_address') or '-')}</div>
        {criticality_pill(server.get("criticality"))}
        {status_pill(server.get("is_active"))}
        {env_pill(server.get("environment"))}
        {zone_pill(server.get("zone"))}
        <div class="hint">{html.escape(hint)}</div>
    </div>
    """


def render_selected_server_banner(server, context_label="현재 선택 서버"):
    if not server:
        st.markdown(
            """
            <div class="selected-server-empty">
                현재 선택된 서버가 없습니다. 빠른 서버 선택 카드 또는 보조 선택기에서 서버를 선택해 주세요.
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    st.markdown(
        _selected_server_markup(
            server,
            context_label=context_label,
            hint="아래 상세 탭과 수정 탭은 이 서버를 기준으로 동작합니다.",
            css_class="selected-server-banner",
        ),
        unsafe_allow_html=True,
    )


def render_selected_server_focus_card(server, mode="edit"):
    if not server:
        st.info("선택된 서버가 없어 현재 작업 대상을 표시할 수 없습니다.")
        return

    hint = (
        "아래 저장은 현재 선택된 서버에 적용됩니다."
        if mode == "edit"
        else "상세 정보는 현재 선택된 서버를 기준으로 표시됩니다."
    )
    label = "현재 수정 대상" if mode == "edit" else "현재 상세 조회 대상"
    st.markdown(
        _selected_server_markup(
            server,
            context_label=label,
            hint=hint,
            css_class="selected-server-focus",
        ),
        unsafe_allow_html=True,
    )


def build_server_inventory_display_df(df: pd.DataFrame):
    if df is None or df.empty:
        return df

    display = df.copy()
    display["서버명"] = display["server_name"]
    display["Hostname"] = display["hostname"].fillna("")
    display["IP"] = display["ip_address"].fillna("")
    display["운영구분"] = display["environment"].apply(env_badge_text)
    display["Zone"] = display["zone"].apply(zone_badge_text)
    display["중요도"] = display["criticality"].apply(criticality_badge_text)
    display["상태"] = display["is_active"].apply(lambda value: "운영중" if value else "비활성")
    display["업로드"] = display["upload_enabled"].apply(lambda value: "가능" if value else "제한")
    display["서비스"] = display["service_name"].fillna("")
    display["담당"] = display["owner_name"].fillna("")
    if "updated_at" in display.columns:
        display["최근 수정"] = display["updated_at"].astype(str).str.replace("T", " ", regex=False)
    return display[
        [
            "서버명",
            "Hostname",
            "IP",
            "운영구분",
            "Zone",
            "중요도",
            "상태",
            "업로드",
            "서비스",
            "담당",
            "최근 수정",
        ]
    ]


def style_server_inventory_table(df: pd.DataFrame):
    if df is None or df.empty:
        return df

    def style_level(value):
        mapping = {
            "Critical": "background-color:#fee2e2;color:#991b1b;font-weight:700;",
            "High": "background-color:#ffedd5;color:#9a3412;font-weight:700;",
            "Medium": "background-color:#fef3c7;color:#92400e;font-weight:700;",
            "Low": "background-color:#dcfce7;color:#166534;font-weight:700;",
            "운영중": "background-color:#dcfce7;color:#166534;font-weight:700;",
            "비활성": "background-color:#e5e7eb;color:#374151;font-weight:700;",
            "가능": "background-color:#dbeafe;color:#1d4ed8;font-weight:700;",
            "제한": "background-color:#e5e7eb;color:#475569;font-weight:700;",
            "PROD": "background-color:#fee2e2;color:#991b1b;font-weight:700;",
            "DMZ": "background-color:#fee2e2;color:#991b1b;font-weight:700;",
        }
        return mapping.get(value, "")

    return df.style.map(style_level, subset=["중요도", "상태", "업로드", "운영구분", "Zone"])


def build_scan_run_display_df(df: pd.DataFrame):
    if df is None or df.empty:
        return df

    display = df.copy()
    display["최신"] = display["latest_for_server"].apply(lambda value: "최신" if value else "")
    display["서버명"] = display["server_name"].fillna("미연결 서버")
    display["Hostname"] = display["hostname"].fillna("")
    display["입력 유형"] = display["input_type"].apply(input_type_badge_text)
    display["정책"] = display["policy_name"].fillna("정책 미지정")
    display["탐지 건수"] = display["findings_count"].fillna(0).astype(int)
    display["점검 루트"] = display["roots_count"].fillna(0).astype(int)
    display["스캔 파일"] = display["scanned_files"].fillna(0).astype(int)
    display["실행 시각"] = display["generated_at"].fillna(display["scan_started_at"]).fillna("")
    display["리포트 파일"] = display["file_name"].fillna("")
    return display[
        [
            "최신",
            "서버명",
            "Hostname",
            "입력 유형",
            "정책",
            "탐지 건수",
            "점검 루트",
            "스캔 파일",
            "실행 시각",
            "리포트 파일",
        ]
    ]


def style_scan_run_table(df: pd.DataFrame):
    if df is None or df.empty:
        return df

    def style_cell(value):
        if value == "최신":
            return "background-color:#ecfeff;color:#155e75;font-weight:700;"
        if isinstance(value, (int, float)):
            if value >= 50:
                return "background-color:#fee2e2;color:#991b1b;font-weight:700;"
            if value >= 10:
                return "background-color:#ffedd5;color:#9a3412;font-weight:700;"
        if value in INPUT_TYPE_LABELS.values():
            return "background-color:#eff6ff;color:#1d4ed8;font-weight:700;"
        return ""

    return df.style.map(style_cell, subset=["최신", "입력 유형", "탐지 건수"])


def render_server_identity(server):
    st.markdown(
        f"### {server.get('server_name', '-')}\n"
        f"`{server.get('hostname') or '-'} / {server.get('ip_address') or '-'}`"
    )


def render_server_overview(server):
    top = st.columns(4)
    top[0].markdown(criticality_pill(server.get("criticality")), unsafe_allow_html=True)
    top[1].markdown(status_pill(server.get("is_active")), unsafe_allow_html=True)
    top[2].markdown(env_pill(server.get("environment")), unsafe_allow_html=True)
    top[3].markdown(zone_pill(server.get("zone")), unsafe_allow_html=True)

    mid = st.columns(4)
    mid[0].metric("웹서버", (server.get("web_server_type") or "-").upper())
    mid[1].metric("OS", (server.get("os_type") or "-").upper())
    mid[2].metric("서비스명", server.get("service_name") or "-")
    mid[3].markdown(upload_pill(server.get("upload_enabled")), unsafe_allow_html=True)

    info_col1, info_col2 = st.columns(2)
    with info_col1:
        st.write(f"**담당자 / 부서**: {server.get('owner_name') or '-'}")
        st.write(f"**생성 시각**: {server.get('created_at') or '-'}")
    with info_col2:
        st.write(f"**수정 시각**: {server.get('updated_at') or '-'}")
        st.write(f"**비고**: {server.get('notes') or '-'}")


def render_server_selection_cards(df: pd.DataFrame, selected_server_id, key_prefix="inventory-card"):
    if df is None or df.empty:
        st.info("선택 가능한 서버가 없습니다.")
        return selected_server_id

    card_df = df.head(8).copy()
    next_selected = selected_server_id

    st.markdown("### 빠른 서버 선택")
    st.caption("운영 우선순위가 높은 서버를 카드로 먼저 보여줍니다. 카드를 눌러 상세/수정 대상으로 선택해 주세요.")

    columns = st.columns(2)
    for index, (_, row) in enumerate(card_df.iterrows()):
        with columns[index % 2]:
            selected = row["id"] == selected_server_id
            css_class = "server-card selected" if selected else "server-card"
            st.markdown(
                f"""
                <div class="{css_class}">
                    <h4>{html.escape(row.get("server_name") or "-")}</h4>
                    <div class="meta">{html.escape(row.get("hostname") or "-")} / {html.escape(row.get("ip_address") or "-")}</div>
                    {criticality_pill(row.get("criticality"))}
                    {status_pill(row.get("is_active"))}
                    {upload_pill(row.get("upload_enabled"))}
                    {env_pill(row.get("environment"))}
                    {zone_pill(row.get("zone"))}
                    <div class="service">{html.escape(row.get("service_name") or "서비스 미정")}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            label = "현재 선택됨" if selected else "이 서버 선택"
            if st.button(label, key=f"{key_prefix}-{row['id']}", width="stretch", disabled=selected):
                next_selected = row["id"]

    return next_selected


def render_run_selection_cards(df: pd.DataFrame, selected_run_id, key_prefix="run-card"):
    if df is None or df.empty:
        st.info("우선 확인할 실행 이력이 없습니다.")
        return selected_run_id

    card_df = df.head(4).copy()
    next_selected = selected_run_id

    st.markdown("### 우선 확인 실행")
    st.caption("최신 실행과 탐지 건수가 많은 실행을 먼저 확인할 수 있도록 상위 실행을 카드로 보여줍니다.")

    columns = st.columns(2)
    for index, (_, row) in enumerate(card_df.iterrows()):
        with columns[index % 2]:
            selected = row["id"] == selected_run_id
            css_class = "run-card selected" if selected else "run-card"
            st.markdown(
                f"""
                <div class="{css_class}">
                    <h4>{html.escape(row.get("server_name") or "미연결 서버")}</h4>
                    <div class="meta">{html.escape(row.get("generated_at") or row.get("scan_started_at") or "-")}</div>
                    {latest_run_pill(row.get("latest_for_server"))}
                    {findings_count_pill(row.get("findings_count"))}
                    {input_type_pill(row.get("input_type"))}
                    <div class="service">{html.escape(row.get("policy_name") or "정책 미지정")}</div>
                    <div class="hint">루트 {int(row.get("roots_count") or 0)}개 / 스캔 파일 {int(row.get("scanned_files") or 0)}개</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            label = "현재 선택됨" if selected else "이 실행 보기"
            if st.button(label, key=f"{key_prefix}-{row['id']}", width="stretch", disabled=selected):
                next_selected = row["id"]

    return next_selected


def render_scan_run_overview(run):
    summary = st.columns(4)
    summary[0].markdown(latest_run_pill(run.get("latest_for_server")), unsafe_allow_html=True)
    summary[1].markdown(findings_count_pill(run.get("findings_count")), unsafe_allow_html=True)
    summary[2].markdown(input_type_pill(run.get("input_type")), unsafe_allow_html=True)
    summary[3].metric("스캐너 버전", run.get("scanner_version") or "-")

    metrics = st.columns(4)
    metrics[0].metric("서버", run.get("server_name") or "미연결 서버")
    metrics[1].metric("정책", run.get("policy_name") or "정책 미지정")
    metrics[2].metric("점검 루트", int(run.get("roots_count") or 0))
    metrics[3].metric("스캔 파일", int(run.get("scanned_files") or 0))

    info_col1, info_col2 = st.columns(2)
    with info_col1:
        st.write(f"**실행 시각**: {run.get('scan_started_at') or run.get('generated_at') or '-'}")
        st.write(f"**Hostname**: {run.get('hostname') or '-'}")
        st.write(f"**환경 / Zone**: {env_badge_text(run.get('environment'))} / {zone_badge_text(run.get('zone'))}")
        st.write(f"**리포트 파일**: {run.get('file_name') or '-'}")
    with info_col2:
        st.write(f"**원본 리포트 경로**: {run.get('original_path') or '-'}")
        st.write(f"**저장 경로**: {run.get('stored_path') or '-'}")
        st.write(f"**점검 실행 ID**: {run.get('id') or '-'}")
