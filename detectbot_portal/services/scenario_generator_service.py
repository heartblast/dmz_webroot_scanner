from __future__ import annotations

import json
import re
from copy import deepcopy
from pathlib import Path

try:
    from detectbot_portal.services.option_generator_service import (
        DEFAULT_ALLOW_EXTS,
        DEFAULT_ALLOW_MIME_PREFIXES,
        DEFAULT_CONTENT_EXTS,
        DEFAULT_PII_EXTS,
    )
except ModuleNotFoundError:
    from services.option_generator_service import (
        DEFAULT_ALLOW_EXTS,
        DEFAULT_ALLOW_MIME_PREFIXES,
        DEFAULT_CONTENT_EXTS,
        DEFAULT_PII_EXTS,
    )


SCENARIO_PRESET_FILE = Path(__file__).resolve().parents[1] / "data" / "scenario_presets.json"
SAFE_OUTPUT_PATH = "/tmp/dmz_webroot_scan_report.json"

ADVANCED_KEYS = [
    "newer_than_h",
    "max_depth",
    "workers",
    "max_size_mb",
    "follow_symlink",
    "hash_enabled",
    "allow_mime_prefixes",
    "allow_exts",
    "enable_rules",
    "disable_rules",
    "excludes",
    "content_scan",
    "content_max_bytes",
    "content_max_size_kb",
    "content_exts",
    "pii_scan",
    "pii_max_bytes",
    "pii_max_size_kb",
    "pii_max_matches",
    "pii_exts",
    "pii_mask",
    "pii_store_sample",
    "pii_context_keywords",
    "kafka_enabled",
    "kafka_brokers",
    "kafka_topic",
    "kafka_client_id",
    "kafka_tls",
    "kafka_sasl_enabled",
    "kafka_username",
    "kafka_password_env",
    "kafka_mask_sensitive",
]

DEFAULT_EXCLUDES = ["/var/cache", "/tmp", "/var/tmp", "node_modules"]
STATIC_ASSET_EXTS = [
    ".html", ".htm", ".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif",
    ".svg", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".otf",
]
STATIC_ASSET_MIME_PREFIXES = [
    "text/html", "text/css", "application/javascript", "text/javascript",
    "image/", "font/", "application/font-",
]
CONFIG_SENSITIVE_EXTS = [
    ".env", ".yaml", ".yml", ".json", ".xml", ".properties", ".conf",
    ".ini", ".txt", ".config", ".cfg", ".toml",
]
PII_FOCUSED_EXTS = [
    ".yaml", ".yml", ".json", ".xml", ".properties", ".conf",
    ".ini", ".txt", ".log", ".csv", ".tsv",
]

INTENSITY_PROFILES = {
    "safe": {
        "label": "안전 점검",
        "description": "운영 영향이 가장 적은 빠른 일상 점검용 설정입니다.",
        "load": "낮음",
        "defaults": {
            "newer_than_h": 24, "max_depth": 6, "workers": 2, "hash_enabled": False,
            "content_max_bytes": 32768, "content_max_size_kb": 256,
            "pii_max_bytes": 32768, "pii_max_size_kb": 128, "pii_max_matches": 3,
            "max_size_mb": 80,
        },
    },
    "balanced": {
        "label": "균형 점검",
        "description": "범위와 운영 안정성을 함께 고려한 기본 설정입니다.",
        "load": "보통",
        "defaults": {
            "newer_than_h": 72, "max_depth": 10, "workers": 4, "hash_enabled": False,
            "content_max_bytes": 65536, "content_max_size_kb": 1024,
            "pii_max_bytes": 65536, "pii_max_size_kb": 256, "pii_max_matches": 5,
            "max_size_mb": 100,
        },
    },
    "deep": {
        "label": "정밀 점검",
        "description": "사고 대응이나 인수인계 검토에 맞춘 넓은 범위의 설정입니다.",
        "load": "높음",
        "defaults": {
            "newer_than_h": 168, "max_depth": 18, "workers": 6, "hash_enabled": True,
            "content_max_bytes": 131072, "content_max_size_kb": 2048,
            "pii_max_bytes": 131072, "pii_max_size_kb": 512, "pii_max_matches": 10,
            "max_size_mb": 150,
        },
    },
}

SCENARIOS = {
    "staging": {
        "label": "반출 대기 파일 점검",
        "summary": "업로드되었거나 임시 적재된 대용량 파일과 압축 파일을 중점적으로 확인합니다.",
        "recommended_for": "업로드가 많은 서비스, 반출 징후 점검",
        "risk_focus": "최근 파일, 대용량 파일, 압축 파일, 확장자/MIME 불일치",
        "why": "임시 적재 파일은 직접 노출 경로로 이어질 가능성이 큽니다.",
    },
    "residual": {
        "label": "잔존 파일 점검",
        "summary": "로그, 덤프, 백업, 임시 파일, 추적 파일의 잔존 여부를 확인합니다.",
        "recommended_for": "운영 위생 점검, 배포 후 정리 상태 검토",
        "risk_focus": "log, bak, tmp, dump, trace, core 계열 잔존 파일",
        "why": "운영 잔여 파일은 내부 구조나 계정 정보를 노출할 수 있습니다.",
    },
    "exports": {
        "label": "업무 산출물 점검",
        "summary": "웹 경로 아래에 남아 있는 CSV, JSON, SQL, XLSX, TXT 산출물을 확인합니다.",
        "recommended_for": "배치, 리포트, 데이터 추출 엔드포인트",
        "risk_focus": "업무 산출물과 생성 결과 파일",
        "why": "생성된 산출물이 웹 경로에 남아 있으면 직접 다운로드로 이어질 수 있습니다.",
    },
    "secrets": {
        "label": "설정/비밀정보 노출 점검",
        "summary": "설정 파일, 토큰, 비밀정보 패턴이 포함된 본문을 중점적으로 확인합니다.",
        "recommended_for": "배포 검증, 보안 점검",
        "risk_focus": ".env, yaml, json, xml, properties, conf, ini, txt 및 본문 패턴",
        "why": "설정과 비밀정보 노출은 2차 침해로 이어질 위험이 큽니다.",
    },
    "integrated": {
        "label": "통합 기본 점검",
        "summary": "잔존 파일, 반출 징후, 비밀정보 노출을 균형 있게 확인하는 기본 시나리오입니다.",
        "recommended_for": "정기 기준선 점검",
        "risk_focus": "허용 목록 위반, 위험 확장자, 대용량 파일, 비밀정보 본문",
        "why": "세부 조정 없이도 넓은 범위를 실용적으로 확인할 수 있습니다.",
    },
}

RECOMMENDED_PACKS = {
    "safe_check": {"label": "안전 점검 팩", "subtitle": "운영 영향이 적은 일상 점검용 추천 조합입니다.", "scenarios": ["residual", "integrated"], "intensity": "safe"},
    "exfil_signs": {"label": "반출 징후 팩", "subtitle": "업로드 및 임시 적재 경로를 우선 확인합니다.", "scenarios": ["staging"], "intensity": "balanced"},
    "config_exposure": {"label": "설정 노출 팩", "subtitle": "설정 파일과 비밀정보 노출 여부를 중점 점검합니다.", "scenarios": ["secrets"], "intensity": "balanced"},
    "incident_deep": {"label": "사고 대응 정밀 팩", "subtitle": "사고 대응 상황에서 더 넓은 범위를 점검합니다.", "scenarios": ["staging", "residual", "secrets"], "intensity": "deep"},
}


def non_empty_lines(text: str) -> list[str]:
    return [line.strip() for line in (text or "").splitlines() if line.strip()]


def _dedupe(items: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        value = str(item).strip()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _remove_items(base: list[str], targets: list[str]) -> list[str]:
    target_set = {item.lower() for item in targets}
    return [item for item in base if item.lower() not in target_set]


def default_config() -> dict:
    return {
        "preset": "",
        "purpose": "Scenario Wizard",
        "server_type": "nginx",
        "nginx_input_mode": "Dump File Path",
        "nginx_dump_path": "",
        "apache_input_mode": "Dump File Path",
        "apache_dump_path": "",
        "watch_dirs": [],
        "newer_than_h": 72,
        "max_depth": 10,
        "workers": 4,
        "follow_symlink": False,
        "max_size_mb": 100,
        "hash_enabled": False,
        "allow_mime_prefixes": list(DEFAULT_ALLOW_MIME_PREFIXES),
        "allow_exts": list(DEFAULT_ALLOW_EXTS),
        "enable_rules": [],
        "disable_rules": [],
        "content_scan": False,
        "content_max_bytes": 65536,
        "content_max_size_kb": 1024,
        "content_exts": list(DEFAULT_CONTENT_EXTS),
        "pii_scan": False,
        "pii_max_bytes": 65536,
        "pii_max_size_kb": 256,
        "pii_max_matches": 5,
        "pii_exts": list(DEFAULT_PII_EXTS),
        "pii_mask": True,
        "pii_store_sample": True,
        "pii_context_keywords": True,
        "excludes": list(DEFAULT_EXCLUDES),
        "output_path": SAFE_OUTPUT_PATH,
        "kafka_enabled": False,
        "kafka_brokers": "",
        "kafka_topic": "",
        "kafka_client_id": "detectbot",
        "kafka_tls": False,
        "kafka_sasl_enabled": False,
        "kafka_username": "",
        "kafka_password_env": "",
        "kafka_mask_sensitive": True,
    }


def build_scenario_config(
    *,
    selected_scenarios: list[str],
    intensity: str,
    server_type: str,
    nginx_mode: str,
    nginx_dump_path: str,
    apache_mode: str,
    apache_dump_path: str,
    extra_watch_dirs_text: str,
    selected_candidates: list[str],
    unselected_candidates: list[str],
    output_path: str,
) -> dict:
    config = default_config()
    intensity_key = intensity if intensity in INTENSITY_PROFILES else "balanced"
    config.update(deepcopy(INTENSITY_PROFILES[intensity_key]["defaults"]))
    config["server_type"] = server_type
    config["nginx_input_mode"] = nginx_mode
    config["nginx_dump_path"] = nginx_dump_path.strip()
    config["apache_input_mode"] = apache_mode
    config["apache_dump_path"] = apache_dump_path.strip()
    config["output_path"] = output_path.strip() or SAFE_OUTPUT_PATH
    watch_dirs = list(selected_candidates) if server_type == "manual" else []
    watch_dirs.extend(non_empty_lines(extra_watch_dirs_text))
    config["watch_dirs"] = _dedupe(watch_dirs)
    config["excludes"] = _dedupe(config["excludes"] + list(unselected_candidates))
    active = _dedupe(selected_scenarios) or ["integrated"]
    for scenario_id in active:
        _apply_scenario(config, scenario_id, intensity_key)
    if server_type == "manual":
        config["nginx_dump_path"] = ""
        config["apache_dump_path"] = ""
    elif server_type == "nginx":
        config["apache_dump_path"] = ""
    elif server_type == "apache":
        config["nginx_dump_path"] = ""
    return config


def _apply_scenario(config: dict, scenario_id: str, intensity: str) -> None:
    if scenario_id == "staging":
        config["content_scan"] = config["content_scan"] or intensity == "deep"
        config["hash_enabled"] = config["hash_enabled"] or intensity == "deep"
        config["max_size_mb"] = max(config["max_size_mb"], 120 if intensity == "deep" else 100)
    elif scenario_id == "residual":
        config["newer_than_h"] = min(config["newer_than_h"], 72 if intensity != "deep" else 168)
        config["allow_exts"] = _remove_items(config["allow_exts"], [".map"])
    elif scenario_id == "exports":
        config["allow_exts"] = list(STATIC_ASSET_EXTS)
        config["allow_mime_prefixes"] = list(STATIC_ASSET_MIME_PREFIXES)
        config["content_scan"] = config["content_scan"] or intensity == "deep"
    elif scenario_id == "secrets":
        config["allow_exts"] = list(STATIC_ASSET_EXTS)
        config["allow_mime_prefixes"] = list(STATIC_ASSET_MIME_PREFIXES)
        config["content_scan"] = True
        config["content_exts"] = list(CONFIG_SENSITIVE_EXTS)
        if intensity == "deep":
            config["pii_scan"] = True
            config["pii_exts"] = list(PII_FOCUSED_EXTS)
    elif scenario_id == "integrated":
        config["content_scan"] = True
        if intensity == "deep":
            config["pii_scan"] = True
            config["pii_exts"] = list(PII_FOCUSED_EXTS)


def parse_auto_extracted_paths(server_type: str, dump_path: str) -> list[dict]:
    path = dump_path.strip()
    if server_type not in {"nginx", "apache"} or not path:
        return []
    file_path = Path(path)
    if not file_path.exists() or not file_path.is_file():
        return []
    text = file_path.read_text(encoding="utf-8", errors="ignore")
    return _parse_nginx_dump(text) if server_type == "nginx" else _parse_apache_dump(text)


def _parse_nginx_dump(text: str) -> list[dict]:
    candidates = []
    server_name = ""
    file_hint = ""
    root_re = re.compile(r"^\s*(root|alias)\s+([^;#]+);", re.IGNORECASE)
    file_re = re.compile(r"^#\s*configuration\s+file\s+(.+?):(\d+)", re.IGNORECASE)
    server_re = re.compile(r"^\s*server_name\s+([^;#]+);", re.IGNORECASE)
    for raw_line in text.splitlines():
        line = raw_line.strip()
        file_match = file_re.match(line)
        if file_match:
            file_hint = f"{file_match.group(1).strip()}:{file_match.group(2)}"
            continue
        server_match = server_re.match(line)
        if server_match:
            server_name = server_match.group(1).strip()
            continue
        root_match = root_re.match(line)
        if not root_match:
            continue
        hint_parts = [root_match.group(1).lower()]
        if server_name:
            hint_parts.append(f"server_name={server_name}")
        if file_hint:
            hint_parts.append(file_hint)
        candidates.append(
            {"path": root_match.group(2).strip().strip('"').strip("'"), "source": f"nginx {root_match.group(1).lower()}", "hint": " | ".join(hint_parts)}
        )
    return _dedupe_candidate_rows(candidates)


def _parse_apache_dump(text: str) -> list[dict]:
    candidates = []
    document_root_re = re.compile(r'\bDocumentRoot\s+"?([^"\r\n]+)"?', re.IGNORECASE)
    for match in document_root_re.finditer(text):
        candidates.append({"path": match.group(1).strip().strip('"').strip("'"), "source": "apache documentroot", "hint": "apachectl -S dump"})
    return _dedupe_candidate_rows(candidates)


def _dedupe_candidate_rows(rows: list[dict]) -> list[dict]:
    seen: set[str] = set()
    out = []
    for row in rows:
        path = row["path"].strip()
        if not path or path in seen:
            continue
        seen.add(path)
        out.append({"path": path, "source": row["source"], "hint": row["hint"]})
    return out


def summarize_rules(config: dict, selected_scenarios: list[str]) -> list[str]:
    summaries = []
    active = _dedupe(selected_scenarios) or ["integrated"]
    if any(s in active for s in ["staging", "residual", "exports", "integrated"]):
        summaries.append("허용 목록 위반, 위험 확장자, 확장자/MIME 불일치를 함께 점검합니다.")
        summaries.append("웹 경로 아래의 비정상 파일을 폭넓게 확인합니다.")
    if any(s in active for s in ["staging", "integrated"]):
        summaries.append("대용량 파일과 임시 적재 흔적을 더 민감하게 확인합니다.")
    if "exports" in active:
        summaries.append("csv/json/sql/txt/xlsx 같은 산출물을 더 민감한 대상으로 취급합니다.")
    if config.get("content_scan"):
        summaries.append("설정/비밀정보 노출 확인을 위해 본문 점검이 활성화되어 있습니다.")
    if config.get("pii_scan"):
        summaries.append("텍스트 계열 파일에 대해 PII 점검이 활성화되어 있습니다.")
    if config.get("hash_enabled"):
        summaries.append("추적 강화를 위해 SHA-256 해시 계산이 활성화되어 있습니다.")
    return summaries


def summarize_scope(config: dict, auto_candidates: list[dict], selected_candidates: list[str], unselected_candidates: list[str]) -> list[str]:
    scope = []
    if config["server_type"] == "manual":
        scope.append(f"수동 지정 감시 경로: {len(config['watch_dirs'])}개")
    else:
        scope.append(f"자동 추출 후보 경로: {len(auto_candidates)}개")
        if selected_candidates:
            scope.append(f"선택한 자동 추출 경로: {len(selected_candidates)}개")
        if unselected_candidates:
            scope.append(f"제외한 자동 추출 경로: {len(unselected_candidates)}개")
        if config["watch_dirs"]:
            scope.append(f"추가 수동 감시 경로: {len(config['watch_dirs'])}개")
    scope.append(f"최근 {config['newer_than_h']}시간, 깊이 {config['max_depth']}, 작업자 {config['workers']}개 기준")
    return scope


def estimate_load(config: dict) -> tuple[str, str]:
    score = 0
    if config["max_depth"] >= 12:
        score += 1
    if config["newer_than_h"] >= 168 or config["newer_than_h"] == 0:
        score += 1
    if config["hash_enabled"]:
        score += 2
    if config["content_scan"]:
        score += 2
    if config["pii_scan"]:
        score += 2
    if config["workers"] >= 6:
        score += 1
    if score <= 2:
        return "낮음", "운영 영향이 적고 빠르게 수행할 수 있는 구성이에요."
    if score <= 5:
        return "보통", "정기 점검에 적합한 균형형 구성입니다."
    return "높음", "더 넓은 범위와 심화 점검을 수행하므로 실행 영향이 커질 수 있습니다."


def execution_checkpoints(config: dict, server_type: str, selected_candidates: list[str]) -> list[str]:
    checkpoints = []
    if server_type in {"nginx", "apache"} and not selected_candidates:
        checkpoints.append("생성된 명령을 실행하기 전에 자동 추출된 루트 경로를 다시 확인하세요.")
    if config["content_scan"]:
        checkpoints.append("운영 환경에서는 Content Scan 대상 확장자가 과도하게 넓지 않은지 확인하세요.")
    if config["hash_enabled"]:
        checkpoints.append("대량 파일에 해시 계산을 적용하면 추가 I/O가 발생할 수 있습니다.")
    if not config["output_path"]:
        checkpoints.append("JSON 결과 파일 저장 경로를 지정하세요.")
    if server_type == "manual" and not config["watch_dirs"]:
        checkpoints.append("수동 모드에서는 최소 1개 이상의 감시 경로가 필요합니다.")
    return checkpoints


def load_saved_presets() -> dict:
    if not SCENARIO_PRESET_FILE.exists():
        return {}
    try:
        return json.loads(SCENARIO_PRESET_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_preset(name: str, payload: dict) -> None:
    name = name.strip()
    if not name:
        return
    presets = load_saved_presets()
    presets[name] = payload
    SCENARIO_PRESET_FILE.parent.mkdir(parents=True, exist_ok=True)
    SCENARIO_PRESET_FILE.write_text(json.dumps(presets, ensure_ascii=False, indent=2), encoding="utf-8")


def delete_preset(name: str) -> None:
    presets = load_saved_presets()
    if name not in presets:
        return
    presets.pop(name, None)
    SCENARIO_PRESET_FILE.parent.mkdir(parents=True, exist_ok=True)
    SCENARIO_PRESET_FILE.write_text(json.dumps(presets, ensure_ascii=False, indent=2), encoding="utf-8")


def sync_advanced_state(session_state, recommended_config: dict, signature: str) -> None:
    if session_state.get("scenario_wizard_signature") == signature:
        return
    for field in ADVANCED_KEYS:
        state_key = f"scenario_wizard_adv_{field}"
        value = recommended_config.get(field)
        session_state[state_key] = "\n".join(value) if isinstance(value, list) else value
    session_state["scenario_wizard_signature"] = signature


def build_final_config(session_state, recommended_config: dict) -> dict:
    config = deepcopy(recommended_config)
    for field in ADVANCED_KEYS:
        state_key = f"scenario_wizard_adv_{field}"
        if field in {"allow_mime_prefixes", "allow_exts", "enable_rules", "disable_rules", "excludes", "content_exts", "pii_exts"}:
            config[field] = non_empty_lines(session_state.get(state_key, ""))
        else:
            config[field] = session_state.get(state_key, config.get(field))
    config["preset"] = "scenario_wizard"
    return config


def preset_payload(session_state) -> dict:
    keys = [
        "scenario_wizard_server_type",
        "scenario_wizard_nginx_mode",
        "scenario_wizard_nginx_dump_path",
        "scenario_wizard_apache_mode",
        "scenario_wizard_apache_dump_path",
        "scenario_wizard_extra_paths",
        "scenario_wizard_selected_scenarios",
        "scenario_wizard_intensity",
        "scenario_wizard_output_path",
        "scenario_wizard_selected_candidates",
    ]
    payload = {key: session_state.get(key) for key in keys}
    for field in ADVANCED_KEYS:
        payload[f"scenario_wizard_adv_{field}"] = session_state.get(f"scenario_wizard_adv_{field}")
    return payload


def apply_saved_preset(session_state, payload: dict) -> None:
    for key, value in payload.items():
        session_state[key] = value
