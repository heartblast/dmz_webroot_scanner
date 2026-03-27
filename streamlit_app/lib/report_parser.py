"""
Report parsing and analysis functions for DMZ Webroot Scanner.
"""

from collections import Counter

import pandas as pd

from lib.constants import REASON_LABELS, SEVERITY_EMOJI, SEVERITY_ORDER
from lib.utils import fmt_bytes, fmt_dt, normalize_list, severity_rank
from utils.meaning_loader import get_pattern_meaning, get_reason_meaning


def normalize_host_info(report):
    raw_host = report.get("host")
    host = {
        "hostname": "",
        "ip_addresses": [],
        "primary_ip": "",
        "os_type": "알 수 없음",
        "os_name": "",
        "os_version": "",
        "platform": "",
        "collected_at": "",
    }

    if isinstance(raw_host, dict):
        host["hostname"] = str(raw_host.get("hostname") or "").strip()
        host["ip_addresses"] = [
            str(value).strip() for value in normalize_list(raw_host.get("ip_addresses")) if str(value).strip()
        ]
        host["primary_ip"] = str(raw_host.get("primary_ip") or "").strip()
        host["os_type"] = str(raw_host.get("os_type") or "알 수 없음").strip() or "알 수 없음"
        host["os_name"] = str(raw_host.get("os_name") or "").strip()
        host["os_version"] = str(raw_host.get("os_version") or "").strip()
        host["platform"] = str(raw_host.get("platform") or "").strip()
        host["collected_at"] = str(raw_host.get("collected_at") or "").strip()
    elif isinstance(raw_host, str):
        host["hostname"] = raw_host.strip()

    if not host["primary_ip"] and host["ip_addresses"]:
        host["primary_ip"] = host["ip_addresses"][0]

    return host


def normalize_roots(report):
    return normalize_list(report.get("roots") or report.get("scan_roots"))


def host_summary_text(host):
    parts = [part for part in [host.get("hostname"), host.get("primary_ip"), host.get("os_type")] if part]
    return " / ".join(parts) if parts else "알 수 없음"


def build_findings_df(findings):
    """Build pandas DataFrame from findings."""
    rows = []
    for idx, finding in enumerate(findings):
        reasons = normalize_list(finding.get("reasons"))
        matched_patterns = normalize_list(finding.get("matched_patterns"))
        evidence_masked = normalize_list(finding.get("evidence_masked"))
        content_flags = normalize_list(finding.get("content_flags"))

        rows.append(
            {
                "idx": idx,
                "severity": (finding.get("severity") or "unknown").lower(),
                "path": finding.get("path", ""),
                "real_path": finding.get("real_path", ""),
                "ext": finding.get("ext", ""),
                "mime_sniff": finding.get("mime_sniff", ""),
                "size_bytes": finding.get("size_bytes"),
                "size_human": fmt_bytes(finding.get("size_bytes")),
                "mod_time": finding.get("mod_time", ""),
                "mod_time_fmt": fmt_dt(finding.get("mod_time")),
                "perm": finding.get("perm", ""),
                "reasons": reasons,
                "reasons_text": ", ".join(reasons),
                "matched_patterns": matched_patterns,
                "matched_patterns_text": ", ".join(matched_patterns),
                "evidence_masked": evidence_masked,
                "evidence_masked_text": " | ".join(evidence_masked),
                "content_flags": content_flags,
                "content_flags_text": ", ".join(content_flags),
                "url_exposure_heuristic": finding.get("url_exposure_heuristic", ""),
                "root_matched": finding.get("root_matched", ""),
                "root_source": finding.get("root_source", ""),
                "sha256": finding.get("sha256", ""),
            }
        )

    df = pd.DataFrame(rows)
    if df.empty:
        return df

    df["severity_rank"] = df["severity"].apply(severity_rank)
    df = df.sort_values(
        by=["severity_rank", "size_bytes", "mod_time_fmt"],
        ascending=[True, False, False],
        na_position="last",
    ).reset_index(drop=True)
    return df


def render_summary(report):
    """Render summary metrics."""
    import streamlit as st

    stats = report.get("stats", {}) or {}
    roots = normalize_roots(report)
    findings = normalize_list(report.get("findings"))
    host = normalize_host_info(report)

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Host", host_summary_text(host))
    col2.metric("Roots", stats.get("roots_count", len(roots)))
    col3.metric("Scanned Files", stats.get("scanned_files", "-"))
    col4.metric("Findings", stats.get("findings_count", len(findings)))
    col5.metric("Generated At", fmt_dt(report.get("generated_at")))


def render_root_table(roots):
    """Render roots table."""
    import streamlit as st

    if not roots:
        st.info("roots 정보가 없습니다.")
        return

    root_rows = [
        {
            "path": root.get("path", ""),
            "real_path": root.get("real_path", ""),
            "source": root.get("source", ""),
        }
        for root in roots
    ]
    st.dataframe(pd.DataFrame(root_rows), use_container_width=True, hide_index=True)


def render_counters(
    findings_df,
    reason_meaning_getter=None,
    pattern_meaning_getter=None,
):
    """Render severity, reason, and pattern counters."""
    import streamlit as st

    reason_meaning_getter = reason_meaning_getter or get_reason_meaning
    pattern_meaning_getter = pattern_meaning_getter or get_pattern_meaning

    sev_counter = Counter(findings_df["severity"].tolist())
    sev_rows = []
    for sev in SEVERITY_ORDER:
        count = sev_counter.get(sev, 0)
        if count > 0:
            sev_rows.append(
                {
                    "severity": f"{SEVERITY_EMOJI.get(sev, '⬜')} {sev}",
                    "count": count,
                }
            )

    if sev_rows:
        st.dataframe(pd.DataFrame(sev_rows), use_container_width=True, hide_index=True)

    reason_counter = Counter()
    pattern_counter = Counter()

    for _, row in findings_df.iterrows():
        for reason in row["reasons"]:
            reason_counter[reason] += 1
        for pattern in row["matched_patterns"]:
            pattern_counter[pattern] += 1

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### 탐지사유 상위")
        if reason_counter:
            reason_df = pd.DataFrame(
                [
                    {
                        "reason_code": code,
                        "의미": reason_meaning_getter(code),
                        "count": count,
                    }
                    for code, count in reason_counter.most_common(20)
                ]
            )
            st.dataframe(reason_df, use_container_width=True, hide_index=True)
        else:
            st.info("탐지 사유가 없습니다.")

    with col2:
        st.markdown("#### 패턴 탐지 상위")
        if pattern_counter:
            pattern_df = pd.DataFrame(
                [
                    {
                        "pattern": code,
                        "의미": pattern_meaning_getter(code),
                        "count": count,
                    }
                    for code, count in pattern_counter.most_common(20)
                ]
            )
            st.dataframe(pattern_df, use_container_width=True, hide_index=True)
        else:
            st.info("matched_patterns 정보가 없습니다.")


def render_filters(df):
    """Render filtering controls and return filtered DataFrame."""
    import streamlit as st

    st.markdown("### 필터")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        selected_severity = st.multiselect(
            "위험도",
            options=SEVERITY_ORDER,
            default=[sev for sev in SEVERITY_ORDER if sev in df["severity"].unique()],
        )

    all_reasons = sorted({reason for reasons in df["reasons"] for reason in reasons})
    with col2:
        selected_reasons = st.multiselect(
            "탐지 사유",
            options=all_reasons,
            default=[],
            format_func=lambda code: REASON_LABELS.get(code, get_reason_meaning(code)),
        )

    all_patterns = sorted(
        {pattern for patterns in df["matched_patterns"] for pattern in patterns}
    )
    with col3:
        selected_patterns = st.multiselect(
            "탐지 패턴",
            options=all_patterns,
            default=[],
            format_func=lambda code: REASON_LABELS.get(code, get_pattern_meaning(code)),
        )

    with col4:
        keyword = st.text_input("경로/실경로/루트 검색", value="").strip()

    min_size_mb = st.number_input("최소 크기(MB)", min_value=0.0, value=0.0, step=1.0)

    filtered = df.copy()

    if selected_severity:
        filtered = filtered[filtered["severity"].isin(selected_severity)]

    if selected_reasons:
        filtered = filtered[
            filtered["reasons"].apply(
                lambda values: any(value in values for value in selected_reasons)
            )
        ]

    if selected_patterns:
        filtered = filtered[
            filtered["matched_patterns"].apply(
                lambda values: any(value in values for value in selected_patterns)
            )
        ]

    if keyword:
        keyword_lower = keyword.lower()
        filtered = filtered[
            filtered.apply(
                lambda row: keyword_lower in str(row["path"]).lower()
                or keyword_lower in str(row["real_path"]).lower()
                or keyword_lower in str(row["root_matched"]).lower(),
                axis=1,
            )
        ]

    if min_size_mb > 0:
        filtered = filtered[
            filtered["size_bytes"].fillna(0) >= int(min_size_mb * 1024 * 1024)
        ]

    return filtered.reset_index(drop=True)


def interpret_finding(row):
    """Interpret a single finding and return explanation text."""
    reasons = row["reasons"]
    severity = row["severity"]

    lines = [f"위험도는 **{severity}** 입니다."]

    if "high_risk_extension" in reasons:
        lines.append(
            "- 웹 경로에 실행·스크립트·압축 계열의 고위험 확장자 파일이 존재할 가능성이 있습니다."
        )
    if "mime_not_in_allowlist" in reasons:
        lines.append(
            "- 파일 MIME이 허용 정책과 맞지 않아 웹 노출 대상이 아닌 파일일 수 있습니다."
        )
    if "ext_not_in_allowlist" in reasons:
        lines.append(
            "- 파일 확장자가 허용 정책 밖에 있어 업무 목적과 무관한 파일일 가능성이 있습니다."
        )
    if "large_file_in_web_path" in reasons or "large_file" in reasons:
        lines.append(
            "- 웹 경로의 대용량 파일은 스테이징 또는 비정상 반출 준비 흔적일 수 있습니다."
        )
    if "ext_mime_mismatch_image" in reasons or "ext_mime_mismatch_archive" in reasons:
        lines.append(
            "- 확장자와 실제 MIME이 일치하지 않아 위장 파일 가능성을 확인할 필요가 있습니다."
        )

    pii_related = [
        "resident_registration_number",
        "foreigner_registration_number",
        "passport_number",
        "drivers_license",
        "credit_card",
        "bank_account",
        "mobile_phone",
        "email_address",
        "birth_date",
    ]
    if any(code in reasons for code in pii_related):
        lines.append(
            "- 개인정보 패턴이 파일 본문에서 탐지되었습니다. 원문 대신 마스킹된 증거를 우선 확인해 주세요."
        )

    if (
        "secret_patterns" in reasons
        or "private_key_material" in reasons
        or "jdbc_connection_string" in reasons
    ):
        lines.append(
            "- 설정정보, 자격증명, 연결문자열 등 민감정보 노출 위험이 존재할 수 있습니다."
        )

    if row["url_exposure_heuristic"]:
        lines.append(f"- 노출 추정: **{row['url_exposure_heuristic']}**")

    return "\n".join(lines)
