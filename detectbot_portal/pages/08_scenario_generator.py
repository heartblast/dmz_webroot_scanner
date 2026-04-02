import html
import json

import streamlit as st
import streamlit.components.v1 as components
import yaml

try:
    from detectbot_portal.bootstrap import bootstrap_portal
    from detectbot_portal.config.settings import load_settings
    from detectbot_portal.lib.ui import render_portal_header
    from detectbot_portal.services.option_generator_service import build_command, build_config_payload
    from detectbot_portal.services.scenario_generator_service import (
        INTENSITY_PROFILES,
        RECOMMENDED_PACKS,
        SCENARIOS,
        apply_saved_preset,
        build_final_config,
        build_scenario_config,
        delete_preset,
        estimate_load,
        execution_checkpoints,
        load_saved_presets,
        parse_auto_extracted_paths,
        preset_payload,
        save_preset,
        summarize_rules,
        summarize_scope,
        sync_advanced_state,
    )
except ModuleNotFoundError:
    from bootstrap import bootstrap_portal
    from config.settings import load_settings
    from lib.ui import render_portal_header
    from services.option_generator_service import build_command, build_config_payload
    from services.scenario_generator_service import (
        INTENSITY_PROFILES,
        RECOMMENDED_PACKS,
        SCENARIOS,
        apply_saved_preset,
        build_final_config,
        build_scenario_config,
        delete_preset,
        estimate_load,
        execution_checkpoints,
        load_saved_presets,
        parse_auto_extracted_paths,
        preset_payload,
        save_preset,
        summarize_rules,
        summarize_scope,
        sync_advanced_state,
    )


def copy_button(label: str, value: str) -> None:
    escaped_label = html.escape(label)
    escaped_value = json.dumps(value)
    components.html(
        f"""
        <button
          style="width:100%;padding:0.55rem 0.8rem;border:1px solid #d0d7de;border-radius:0.5rem;background:#f8fafc;cursor:pointer;"
          onclick='navigator.clipboard.writeText({escaped_value}); this.innerText="복사됨"; setTimeout(() => this.innerText="{escaped_label}", 1200);'>
          {escaped_label}
        </button>
        """,
        height=44,
    )


st.set_page_config(page_title="DetectBot Portal - Scenario Generator", page_icon="SG", layout="wide")

bootstrap_portal(seed_demo_data=load_settings().auto_seed_demo_data)

render_portal_header("시나리오 생성기", "운영 상황에 맞는 시나리오를 선택해 Detect Bot 옵션을 조합하고 CLI/YAML/JSON까지 바로 생성합니다.")

st.info("기존 streamlit_app 시나리오 생성 UX를 포털 구조에 맞게 옮긴 페이지입니다.")

st.markdown("### 추천 팩")
pack_cols = st.columns(len(RECOMMENDED_PACKS))
for idx, (pack_id, pack) in enumerate(RECOMMENDED_PACKS.items()):
    with pack_cols[idx]:
        with st.container(border=True):
            st.markdown(f"**{pack['label']}**")
            st.caption(pack["subtitle"])
            scenario_names = ", ".join(SCENARIOS[item]["label"] for item in pack["scenarios"])
            st.write(f"적용 시나리오: {scenario_names}")
            st.write(f"강도 프로필: {INTENSITY_PROFILES[pack['intensity']]['label']}")
            if st.button("팩 적용", key=f"scenario_pack_{pack_id}", width="stretch"):
                st.session_state["scenario_wizard_selected_scenarios"] = pack["scenarios"]
                st.session_state["scenario_wizard_intensity"] = pack["intensity"]
                st.rerun()

top_left, top_right = st.columns((1.2, 0.8))

with top_left:
    st.markdown("### 입력")
    st.radio(
        "서버 유형",
        options=["nginx", "apache", "manual"],
        format_func=lambda x: {"nginx": "Nginx", "apache": "Apache", "manual": "수동"}[x],
        key="scenario_wizard_server_type",
    )
    if st.session_state["scenario_wizard_server_type"] == "nginx":
        st.radio(
            "Nginx 입력 방식",
            options=["Dump File Path", "CLI Pipe Command"],
            format_func=lambda x: {"Dump File Path": "덤프 파일 경로", "CLI Pipe Command": "CLI 파이프 명령어"}[x],
            key="scenario_wizard_nginx_mode",
            horizontal=True,
        )
        if st.session_state["scenario_wizard_nginx_mode"] == "Dump File Path":
            st.text_input("Nginx 덤프 파일 경로", key="scenario_wizard_nginx_dump_path", placeholder="/tmp/nginx_dump.txt")
    elif st.session_state["scenario_wizard_server_type"] == "apache":
        st.radio(
            "Apache 입력 방식",
            options=["Dump File Path", "CLI Pipe Command"],
            format_func=lambda x: {"Dump File Path": "덤프 파일 경로", "CLI Pipe Command": "CLI 파이프 명령어"}[x],
            key="scenario_wizard_apache_mode",
            horizontal=True,
        )
        if st.session_state["scenario_wizard_apache_mode"] == "Dump File Path":
            st.text_input("Apache 덤프 파일 경로", key="scenario_wizard_apache_dump_path", placeholder="/tmp/apache_dump.txt")
    else:
        st.text_area("수동 감시 경로", key="scenario_wizard_extra_paths", height=120, placeholder="/var/www/html\n/data/upload")
    st.multiselect(
        "시나리오",
        options=list(SCENARIOS.keys()),
        default=st.session_state.get("scenario_wizard_selected_scenarios", ["integrated"]),
        format_func=lambda item: SCENARIOS[item]["label"],
        key="scenario_wizard_selected_scenarios",
    )
    st.radio(
        "강도",
        options=list(INTENSITY_PROFILES.keys()),
        format_func=lambda key: INTENSITY_PROFILES[key]["label"],
        key="scenario_wizard_intensity",
        horizontal=True,
    )
    st.caption(INTENSITY_PROFILES[st.session_state["scenario_wizard_intensity"]]["description"])
    if st.session_state["scenario_wizard_server_type"] != "manual":
        st.text_area("추가 감시 경로", key="scenario_wizard_extra_paths", height=100, placeholder="/data/upload\n/var/www/extra")
    st.text_input("출력 파일 경로", key="scenario_wizard_output_path", value=st.session_state.get("scenario_wizard_output_path", "/tmp/dmz_webroot_scan_report.json"))

with top_right:
    st.markdown("### 저장된 프리셋")
    saved_presets = load_saved_presets()
    if saved_presets:
        selected_saved_preset = st.selectbox("프리셋 선택", options=[""] + list(saved_presets.keys()), format_func=lambda item: "프리셋을 선택하세요" if item == "" else item)
        col1, col2 = st.columns(2)
        with col1:
            if st.button("불러오기", width="stretch", disabled=selected_saved_preset == ""):
                apply_saved_preset(st.session_state, saved_presets[selected_saved_preset])
                st.rerun()
        with col2:
            if st.button("삭제", width="stretch", disabled=selected_saved_preset == ""):
                delete_preset(selected_saved_preset)
                st.rerun()
    else:
        st.caption("저장된 시나리오 프리셋이 아직 없습니다.")
    preset_name = st.text_input("프리셋 이름", placeholder="예) DMZ-Nginx-Safe")
    if st.button("현재 설정 저장", width="stretch"):
        save_preset(preset_name, preset_payload(st.session_state))
        st.success("프리셋을 저장했습니다.")

server_type = st.session_state.get("scenario_wizard_server_type", "nginx")
nginx_mode = st.session_state.get("scenario_wizard_nginx_mode", "Dump File Path")
nginx_dump_path = st.session_state.get("scenario_wizard_nginx_dump_path", "")
apache_mode = st.session_state.get("scenario_wizard_apache_mode", "Dump File Path")
apache_dump_path = st.session_state.get("scenario_wizard_apache_dump_path", "")
extra_paths_text = st.session_state.get("scenario_wizard_extra_paths", "")
selected_scenarios = st.session_state.get("scenario_wizard_selected_scenarios", ["integrated"])
intensity_key = st.session_state.get("scenario_wizard_intensity", "balanced")
output_path = st.session_state.get("scenario_wizard_output_path", "/tmp/dmz_webroot_scan_report.json")

dump_path = nginx_dump_path if server_type == "nginx" and nginx_mode == "Dump File Path" else ""
if server_type == "apache" and apache_mode == "Dump File Path":
    dump_path = apache_dump_path

auto_candidates = parse_auto_extracted_paths(server_type, dump_path)
all_candidate_paths = [item["path"] for item in auto_candidates]

if server_type != "manual":
    st.markdown("### 자동 추출 경로")
    if auto_candidates:
        default_selected = st.session_state.get("scenario_wizard_selected_candidates", all_candidate_paths)
        filtered_defaults = [item for item in default_selected if item in all_candidate_paths]
        st.session_state["scenario_wizard_selected_candidates"] = filtered_defaults or all_candidate_paths
        st.dataframe(auto_candidates, width="stretch", hide_index=True)
        st.multiselect(
            "선택된 자동 경로",
            options=all_candidate_paths,
            default=st.session_state["scenario_wizard_selected_candidates"],
            key="scenario_wizard_selected_candidates",
        )
    else:
        st.warning("자동 추출된 경로가 없습니다. 덤프 파일 경로를 확인하거나 추가 감시 경로를 입력해 주세요.")

selected_candidates = st.session_state.get("scenario_wizard_selected_candidates", all_candidate_paths if auto_candidates else [])
unselected_candidates = [path for path in all_candidate_paths if path not in selected_candidates]

recommended_config = build_scenario_config(
    selected_scenarios=selected_scenarios,
    intensity=intensity_key,
    server_type=server_type,
    nginx_mode=nginx_mode,
    nginx_dump_path=nginx_dump_path,
    apache_mode=apache_mode,
    apache_dump_path=apache_dump_path,
    extra_watch_dirs_text=extra_paths_text,
    selected_candidates=selected_candidates,
    unselected_candidates=unselected_candidates,
    output_path=output_path,
)

signature = json.dumps(
    {
        "selected_scenarios": selected_scenarios,
        "intensity": intensity_key,
        "server_type": server_type,
        "nginx_mode": nginx_mode,
        "nginx_dump_path": nginx_dump_path,
        "apache_mode": apache_mode,
        "apache_dump_path": apache_dump_path,
        "extra_paths": extra_paths_text,
        "selected_candidates": selected_candidates,
        "output_path": output_path,
    },
    ensure_ascii=False,
    sort_keys=True,
)
sync_advanced_state(st.session_state, recommended_config, signature)

with st.expander("고급 설정", expanded=False):
    col1, col2 = st.columns(2)
    with col1:
        st.number_input("최근 변경 시간(시간)", min_value=0, max_value=720, key="scenario_wizard_adv_newer_than_h")
        st.number_input("최대 탐색 깊이", min_value=1, max_value=30, key="scenario_wizard_adv_max_depth")
        st.number_input("작업 스레드 수", min_value=1, max_value=64, key="scenario_wizard_adv_workers")
        st.number_input("최대 파일 크기(MB)", min_value=1, max_value=2048, key="scenario_wizard_adv_max_size_mb")
        st.checkbox("해시 계산 사용", key="scenario_wizard_adv_hash_enabled")
        st.checkbox("심볼릭 링크 추적", key="scenario_wizard_adv_follow_symlink")
    with col2:
        st.checkbox("콘텐츠 검사 사용", key="scenario_wizard_adv_content_scan")
        st.number_input("콘텐츠 최대 바이트", min_value=128, max_value=1048576, key="scenario_wizard_adv_content_max_bytes")
        st.number_input("콘텐츠 최대 크기(KB)", min_value=1, max_value=102400, key="scenario_wizard_adv_content_max_size_kb")
        st.checkbox("PII 검사 사용", key="scenario_wizard_adv_pii_scan")
        st.number_input("PII 최대 바이트", min_value=128, max_value=1048576, key="scenario_wizard_adv_pii_max_bytes")
        st.number_input("PII 최대 크기(KB)", min_value=1, max_value=102400, key="scenario_wizard_adv_pii_max_size_kb")
        st.number_input("PII 최대 탐지 개수", min_value=1, max_value=100, key="scenario_wizard_adv_pii_max_matches")
    st.text_area("허용 확장자", key="scenario_wizard_adv_allow_exts", height=100)
    st.text_area("허용 MIME Prefix", key="scenario_wizard_adv_allow_mime_prefixes", height=90)
    st.text_area("제외 경로", key="scenario_wizard_adv_excludes", height=90)
    rule_col1, rule_col2 = st.columns(2)
    with rule_col1:
        st.text_area("활성화할 룰", key="scenario_wizard_adv_enable_rules", height=90)
    with rule_col2:
        st.text_area("비활성화할 룰", key="scenario_wizard_adv_disable_rules", height=90)
    st.text_area("콘텐츠 검사 확장자", key="scenario_wizard_adv_content_exts", height=90)
    st.text_area("PII 검사 확장자", key="scenario_wizard_adv_pii_exts", height=90)
    pii_col1, pii_col2 = st.columns(2)
    with pii_col1:
        st.checkbox("PII 마스킹", key="scenario_wizard_adv_pii_mask")
        st.checkbox("PII 샘플 저장", key="scenario_wizard_adv_pii_store_sample")
    with pii_col2:
        st.checkbox("PII 문맥 키워드 사용", key="scenario_wizard_adv_pii_context_keywords")
    with st.expander("Kafka 설정", expanded=False):
        st.checkbox("Kafka 사용", key="scenario_wizard_adv_kafka_enabled")
        st.text_input("Kafka 브로커", key="scenario_wizard_adv_kafka_brokers")
        st.text_input("Kafka 토픽", key="scenario_wizard_adv_kafka_topic")
        st.text_input("Kafka 클라이언트 ID", key="scenario_wizard_adv_kafka_client_id")
        st.checkbox("Kafka TLS 사용", key="scenario_wizard_adv_kafka_tls")
        st.checkbox("Kafka SASL 사용", key="scenario_wizard_adv_kafka_sasl_enabled")
        st.text_input("Kafka 사용자명", key="scenario_wizard_adv_kafka_username")
        st.text_input("Kafka 비밀번호 환경변수", key="scenario_wizard_adv_kafka_password_env")
        st.checkbox("민감정보 마스킹", key="scenario_wizard_adv_kafka_mask_sensitive")

final_config = build_final_config(st.session_state, recommended_config)
command = build_command(final_config)
config_payload = build_config_payload(final_config)
yaml_text = yaml.safe_dump(config_payload, allow_unicode=True, sort_keys=False)
rules_summary = summarize_rules(final_config, selected_scenarios)
scope_summary = summarize_scope(final_config, auto_candidates, selected_candidates, unselected_candidates)
load_level, load_reason = estimate_load(final_config)
checkpoints = execution_checkpoints(final_config, server_type, selected_candidates)

st.markdown("### 생성 결과")
metric_col1, metric_col2, metric_col3 = st.columns(3)
metric_col1.metric("예상 부하", load_level)
metric_col2.metric("자동 후보 경로", len(auto_candidates))
metric_col3.metric("선택된 감시 경로", len(final_config["watch_dirs"]))

left, right = st.columns((1.2, 1))
with left:
    st.markdown("#### CLI 명령어")
    st.code(command, language="bash")
    copy_col1, copy_col2 = st.columns(2)
    with copy_col1:
        copy_button("CLI 복사", command)
    with copy_col2:
        st.download_button("CLI 다운로드", data=command.encode("utf-8"), file_name="dmz_scan_command.sh", mime="text/plain", use_container_width=True)
    st.markdown("#### YAML 미리보기")
    st.code(yaml_text, language="yaml")
    yaml_col1, yaml_col2 = st.columns(2)
    with yaml_col1:
        copy_button("YAML 복사", yaml_text)
    with yaml_col2:
        st.download_button("YAML 다운로드", data=yaml_text.encode("utf-8"), file_name="dmz_scan_config.yaml", mime="text/yaml", use_container_width=True)

with right:
    st.markdown("#### 룰 요약")
    for item in rules_summary:
        st.write(f"- {item}")
    st.markdown("#### 범위 요약")
    for item in scope_summary:
        st.write(f"- {item}")
    st.markdown("#### 부하 판단 근거")
    st.write(load_reason)
    st.markdown("#### 실행 전 체크포인트")
    if checkpoints:
        for item in checkpoints:
            st.write(f"- {item}")
    else:
        st.write("- 바로 실행할 준비가 되었습니다.")

st.markdown("#### JSON 미리보기")
st.code(json.dumps(config_payload, ensure_ascii=False, indent=2), language="json")
st.info("필요하면 생성된 설정을 Option Generator로 가져가 더 세밀하게 조정할 수 있습니다.")
