import streamlit as st
import yaml

from bootstrap import bootstrap_portal
from config.settings import load_settings
from lib.navigation import render_portal_sidebar
from lib.ui import render_portal_header
from services.option_generator_service import (
    RULE_OPTIONS,
    apply_preset_to_session,
    build_command,
    build_config,
    build_config_payload,
    build_notes,
    dumps_json,
    ensure_default_state,
    input_mode_label,
    preset_names,
    preset_label,
    purpose_label,
    purpose_options,
    server_type_label,
)


st.set_page_config(page_title="DetectBot Portal - Option Generator", page_icon="OG", layout="wide")

settings = load_settings()
bootstrap_portal(seed_demo_data=settings.auto_seed_demo_data)
ensure_default_state(st.session_state)
render_portal_sidebar(settings)

render_portal_header("옵션 생성기", "DetectBot Portal 환경에 맞춰 스캔 실행 옵션을 빠르게 조합하고 CLI/YAML/JSON으로 확인합니다.")

preset_col1, preset_col2 = st.columns((1.2, 1))
with preset_col1:
    preset_name = st.selectbox(
        "프리셋",
        options=preset_names(),
        index=preset_names().index(st.session_state.get("option_preset_name", "Balanced Mode")),
        format_func=preset_label,
    )
with preset_col2:
    if st.button("프리셋 적용", width="stretch"):
        apply_preset_to_session(st.session_state, preset_name)
        st.rerun()

left, right = st.columns((1.2, 1))

with left:
    st.subheader("입력 옵션")
    st.radio("운영 목적", purpose_options(), format_func=purpose_label, key="option_purpose")
    st.selectbox("서버 유형", ["nginx", "apache", "manual"], format_func=server_type_label, key="option_server_type")

    if st.session_state["option_server_type"] == "nginx":
        st.selectbox("Nginx 입력 방식", ["Dump File Path", "Pipe Command"], format_func=input_mode_label, key="option_nginx_input_mode")
        if st.session_state["option_nginx_input_mode"] == "Dump File Path":
            st.text_input("Nginx 덤프 파일 경로", key="option_nginx_dump_path", placeholder="/tmp/nginx_dump.txt")
    elif st.session_state["option_server_type"] == "apache":
        st.selectbox("Apache 입력 방식", ["Dump File Path", "Pipe Command"], format_func=input_mode_label, key="option_apache_input_mode")
        if st.session_state["option_apache_input_mode"] == "Dump File Path":
            st.text_input("Apache 덤프 파일 경로", key="option_apache_dump_path", placeholder="/tmp/apache_dump.txt")
    else:
        st.info("수동 모드에서는 감시 대상 경로만 사용합니다.")

    st.text_area(
        "감시 디렉터리",
        key="option_watch_dirs_text",
        height=110,
        placeholder="/var/www/html\n/data/upload",
    )

    c1, c2 = st.columns(2)
    with c1:
        st.number_input("최근 변경 시간(시간)", min_value=0, max_value=720, key="option_newer_than_h")
        st.number_input("최대 탐색 깊이", min_value=1, max_value=30, key="option_max_depth")
        st.number_input("작업 스레드 수", min_value=1, max_value=64, key="option_workers")
    with c2:
        st.number_input("최대 파일 크기(MB)", min_value=1, max_value=102400, key="option_max_size_mb")
        st.checkbox("심볼릭 링크 추적", key="option_follow_symlink")
        st.checkbox("SHA-256 해시 계산", key="option_hash_enabled")

    st.markdown("#### 허용 목록")
    st.text_area("허용 MIME Prefix", key="option_allow_mime_prefixes", height=120)
    st.text_area("허용 확장자", key="option_allow_exts", height=150)

    st.markdown("#### 룰 설정")
    st.text_area("활성화할 룰", key="option_enable_rules_text", height=90, placeholder="high_risk_extension")
    st.text_area("비활성화할 룰", key="option_disable_rules_text", height=90, placeholder="large_file_in_web_path")
    with st.expander("지원 룰 코드"):
        st.code("\n".join(RULE_OPTIONS), language="text")

    st.markdown("#### 콘텐츠 검사")
    st.checkbox("콘텐츠 검사 사용", key="option_content_scan")
    if st.session_state.get("option_content_scan"):
        cc1, cc2 = st.columns(2)
        with cc1:
            st.number_input("콘텐츠 최대 바이트", min_value=128, max_value=1048576, key="option_content_max_bytes")
        with cc2:
            st.number_input("콘텐츠 최대 크기(KB)", min_value=1, max_value=102400, key="option_content_max_size_kb")
        st.text_area("콘텐츠 검사 확장자", key="option_content_exts", height=120)

    st.markdown("#### PII 검사")
    st.checkbox("PII 검사 사용", key="option_pii_scan")
    if st.session_state.get("option_pii_scan"):
        pc1, pc2 = st.columns(2)
        with pc1:
            st.number_input("PII 최대 바이트", min_value=128, max_value=1048576, key="option_pii_max_bytes")
            st.number_input("PII 최대 탐지 개수", min_value=1, max_value=100, key="option_pii_max_matches")
        with pc2:
            st.number_input("PII 최대 크기(KB)", min_value=1, max_value=102400, key="option_pii_max_size_kb")
        st.text_area("PII 검사 확장자", key="option_pii_exts", height=120)
        st.checkbox("PII 마스킹", key="option_pii_mask")
        st.checkbox("PII 샘플 저장", key="option_pii_store_sample")
        st.checkbox("PII 문맥 키워드 사용", key="option_pii_context_keywords")

    st.text_area("제외 경로", key="option_excludes_text", height=120)
    st.text_input("출력 파일 경로", key="option_output_path")

    with st.expander("Kafka 설정"):
        st.checkbox("Kafka 사용", key="option_kafka_enabled")
        if st.session_state.get("option_kafka_enabled"):
            st.text_input("Kafka 브로커", key="option_kafka_brokers", placeholder="broker1:9092,broker2:9092")
            st.text_input("Kafka 토픽", key="option_kafka_topic", placeholder="dmz.scan.findings")
            st.text_input("Kafka 클라이언트 ID", key="option_kafka_client_id")
            st.checkbox("Kafka TLS 사용", key="option_kafka_tls")
            st.checkbox("Kafka SASL 사용", key="option_kafka_sasl_enabled")
            st.text_input("Kafka 사용자명", key="option_kafka_username")
            st.text_input("Kafka 비밀번호 환경변수", key="option_kafka_password_env")
            st.checkbox("민감정보 마스킹", key="option_kafka_mask_sensitive")

config = build_config(st.session_state)
command = build_command(config)
config_payload = build_config_payload(config)
yaml_text = yaml.safe_dump(config_payload, allow_unicode=True, sort_keys=False)
json_text = dumps_json(config_payload)

with right:
    st.subheader("생성 결과")
    a, b, c = st.columns(3)
    a.metric("감시 경로", len(config["watch_dirs"]))
    b.metric("허용 확장자", len(config["allow_exts"]))
    c.metric("제외 경로", len(config["excludes"]))

    st.markdown("#### CLI 명령어")
    st.code(command, language="bash")
    st.download_button(
        "명령어 다운로드",
        data=command.encode("utf-8"),
        file_name="dmz_scan_command.sh",
        mime="text/plain",
        use_container_width=True,
    )

    st.markdown("#### YAML 미리보기")
    st.code(yaml_text, language="yaml")
    st.download_button(
        "YAML 다운로드",
        data=yaml_text.encode("utf-8"),
        file_name="dmz_scan_config.yaml",
        mime="text/yaml",
        use_container_width=True,
    )

    st.markdown("#### JSON 미리보기")
    st.code(json_text, language="json")
    st.download_button(
        "JSON 다운로드",
        data=json_text.encode("utf-8"),
        file_name="dmz_scan_config.json",
        mime="application/json",
        use_container_width=True,
    )

    st.markdown("#### 실행 참고사항")
    for note in build_notes(config):
        st.write(f"- {note}")

with st.expander("사용 가이드", expanded=False):
    st.markdown(
        """
- Nginx는 `nginx -T 2>&1` 결과를 라이브 입력으로 쓰는 방식을 권장합니다.
- Apache는 `apachectl -S 2>&1` 결과와 추가 감시 경로를 함께 지정하는 경우가 많습니다.
- `manual` 모드는 웹 루트 경로를 이미 알고 있을 때 가장 단순하게 사용할 수 있습니다.
- 운영 반영 전에는 최근 변경 시간, 최대 깊이, 제외 경로, 작업 스레드 수를 먼저 조정해 보세요.
        """
    )
