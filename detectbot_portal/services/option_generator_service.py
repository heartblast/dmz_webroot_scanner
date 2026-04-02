from __future__ import annotations

import json
import shlex
from copy import deepcopy


DEFAULT_ALLOW_MIME_PREFIXES = [
    "text/",
    "image/",
    "application/javascript",
    "application/json",
    "application/xml",
]

DEFAULT_ALLOW_EXTS = [
    ".html",
    ".htm",
    ".css",
    ".js",
    ".mjs",
    ".json",
    ".xml",
    ".txt",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".map",
]

DEFAULT_CONTENT_EXTS = [
    ".yaml",
    ".yml",
    ".json",
    ".xml",
    ".properties",
    ".conf",
    ".env",
    ".ini",
    ".txt",
    ".config",
    ".cfg",
    ".toml",
]

DEFAULT_PII_EXTS = [
    ".yaml",
    ".yml",
    ".json",
    ".xml",
    ".properties",
    ".conf",
    ".env",
    ".ini",
    ".txt",
    ".log",
    ".csv",
    ".tsv",
]

RULE_OPTIONS = [
    "mime_not_in_allowlist",
    "ext_not_in_allowlist",
    "high_risk_extension",
    "large_file_in_web_path",
    "ext_mime_mismatch_image",
    "ext_mime_mismatch_archive",
    "secret_patterns",
    "pii_patterns",
]

PRESETS = {
    "Safe Mode": {
        "purpose": "Operations Scan",
        "server_type": "nginx",
        "newer_than_h": 24,
        "max_depth": 8,
        "workers": 4,
        "follow_symlink": False,
        "max_size_mb": 100,
        "hash_enabled": False,
        "allow_mime_prefixes": DEFAULT_ALLOW_MIME_PREFIXES,
        "allow_exts": DEFAULT_ALLOW_EXTS,
        "content_scan": False,
        "content_max_bytes": 65536,
        "content_max_size_kb": 1024,
        "content_exts": DEFAULT_CONTENT_EXTS,
        "pii_scan": False,
        "pii_max_bytes": 65536,
        "pii_max_size_kb": 256,
        "pii_max_matches": 5,
        "pii_exts": DEFAULT_PII_EXTS,
        "pii_mask": True,
        "pii_store_sample": True,
        "pii_context_keywords": True,
        "enable_rules": [],
        "disable_rules": [],
        "excludes": ["/var/cache", "/tmp"],
        "output_path": "/tmp/report.json",
        "kafka_enabled": False,
        "kafka_brokers": "",
        "kafka_topic": "",
        "kafka_client_id": "detectbot",
        "kafka_tls": False,
        "kafka_sasl_enabled": False,
        "kafka_username": "",
        "kafka_password_env": "",
        "kafka_mask_sensitive": True,
    },
    "Balanced Mode": {
        "purpose": "Operations Scan",
        "server_type": "nginx",
        "newer_than_h": 24,
        "max_depth": 10,
        "workers": 4,
        "follow_symlink": False,
        "max_size_mb": 100,
        "hash_enabled": False,
        "allow_mime_prefixes": DEFAULT_ALLOW_MIME_PREFIXES,
        "allow_exts": DEFAULT_ALLOW_EXTS,
        "content_scan": True,
        "content_max_bytes": 65536,
        "content_max_size_kb": 1024,
        "content_exts": DEFAULT_CONTENT_EXTS,
        "pii_scan": False,
        "pii_max_bytes": 65536,
        "pii_max_size_kb": 256,
        "pii_max_matches": 5,
        "pii_exts": DEFAULT_PII_EXTS,
        "pii_mask": True,
        "pii_store_sample": True,
        "pii_context_keywords": True,
        "enable_rules": [],
        "disable_rules": [],
        "excludes": ["/var/cache", "/tmp", "node_modules"],
        "output_path": "/tmp/report.json",
        "kafka_enabled": False,
        "kafka_brokers": "",
        "kafka_topic": "",
        "kafka_client_id": "detectbot",
        "kafka_tls": False,
        "kafka_sasl_enabled": False,
        "kafka_username": "",
        "kafka_password_env": "",
        "kafka_mask_sensitive": True,
    },
    "Deep Mode": {
        "purpose": "Scheduled Scan",
        "server_type": "nginx",
        "newer_than_h": 72,
        "max_depth": 12,
        "workers": 6,
        "follow_symlink": False,
        "max_size_mb": 100,
        "hash_enabled": True,
        "allow_mime_prefixes": DEFAULT_ALLOW_MIME_PREFIXES,
        "allow_exts": DEFAULT_ALLOW_EXTS,
        "content_scan": True,
        "content_max_bytes": 65536,
        "content_max_size_kb": 1024,
        "content_exts": DEFAULT_CONTENT_EXTS,
        "pii_scan": True,
        "pii_max_bytes": 65536,
        "pii_max_size_kb": 256,
        "pii_max_matches": 5,
        "pii_exts": DEFAULT_PII_EXTS,
        "pii_mask": True,
        "pii_store_sample": True,
        "pii_context_keywords": True,
        "enable_rules": [],
        "disable_rules": [],
        "excludes": ["/var/cache"],
        "output_path": "/tmp/report.json",
        "kafka_enabled": False,
        "kafka_brokers": "",
        "kafka_topic": "",
        "kafka_client_id": "detectbot",
        "kafka_tls": False,
        "kafka_sasl_enabled": False,
        "kafka_username": "",
        "kafka_password_env": "",
        "kafka_mask_sensitive": True,
    },
}

PRESET_LABELS = {
    "Safe Mode": "안전 모드",
    "Balanced Mode": "균형 모드",
    "Deep Mode": "정밀 모드",
}

PURPOSE_LABELS = {
    "Test Scan": "테스트 점검",
    "Operations Scan": "운영 점검",
    "Scheduled Scan": "정기 점검",
}

SERVER_TYPE_LABELS = {
    "nginx": "Nginx",
    "apache": "Apache",
    "manual": "수동 경로 지정",
}

INPUT_MODE_LABELS = {
    "Dump File Path": "덤프 파일 경로",
    "Pipe Command": "파이프 명령 실행",
}


def non_empty_lines(text: str) -> list[str]:
    return [line.strip() for line in (text or "").splitlines() if line.strip()]


def csv_or_lines(text: str) -> list[str]:
    items: list[str] = []
    for line in (text or "").splitlines():
        parts = [part.strip() for part in line.split(",") if part.strip()]
        items.extend(parts)
    return items


def preset_names() -> list[str]:
    return list(PRESETS.keys())


def preset_label(name: str) -> str:
    return PRESET_LABELS.get(name, name)


def purpose_options() -> list[str]:
    return list(PURPOSE_LABELS.keys())


def purpose_label(value: str) -> str:
    return PURPOSE_LABELS.get(value, value)


def server_type_label(value: str) -> str:
    return SERVER_TYPE_LABELS.get(value, value)


def input_mode_label(value: str) -> str:
    return INPUT_MODE_LABELS.get(value, value)


def apply_preset_to_session(session_state, preset_name: str) -> None:
    preset = deepcopy(PRESETS[preset_name])
    session_state["option_preset_name"] = preset_name
    for key, value in preset.items():
        session_key = f"option_{key}"
        if isinstance(value, list):
            session_state[session_key] = "\n".join(value)
        else:
            session_state[session_key] = value
    session_state.setdefault("option_nginx_input_mode", "Dump File Path")
    session_state.setdefault("option_apache_input_mode", "Dump File Path")
    session_state.setdefault("option_nginx_dump_path", "")
    session_state.setdefault("option_apache_dump_path", "")
    session_state.setdefault("option_watch_dirs_text", "")


def ensure_default_state(session_state) -> None:
    if "option_preset_name" not in session_state:
        apply_preset_to_session(session_state, "Balanced Mode")


def build_config(session_state) -> dict:
    return {
        "preset": session_state.get("option_preset_name"),
        "purpose": session_state.get("option_purpose"),
        "server_type": session_state.get("option_server_type"),
        "nginx_input_mode": session_state.get("option_nginx_input_mode"),
        "nginx_dump_path": session_state.get("option_nginx_dump_path", ""),
        "apache_input_mode": session_state.get("option_apache_input_mode"),
        "apache_dump_path": session_state.get("option_apache_dump_path", ""),
        "watch_dirs": non_empty_lines(session_state.get("option_watch_dirs_text", "")),
        "newer_than_h": session_state.get("option_newer_than_h"),
        "max_depth": session_state.get("option_max_depth"),
        "workers": session_state.get("option_workers"),
        "follow_symlink": session_state.get("option_follow_symlink"),
        "max_size_mb": session_state.get("option_max_size_mb"),
        "hash_enabled": session_state.get("option_hash_enabled"),
        "allow_mime_prefixes": non_empty_lines(session_state.get("option_allow_mime_prefixes", "")),
        "allow_exts": non_empty_lines(session_state.get("option_allow_exts", "")),
        "enable_rules": csv_or_lines(session_state.get("option_enable_rules_text", "")),
        "disable_rules": csv_or_lines(session_state.get("option_disable_rules_text", "")),
        "content_scan": session_state.get("option_content_scan", False),
        "content_max_bytes": session_state.get("option_content_max_bytes"),
        "content_max_size_kb": session_state.get("option_content_max_size_kb"),
        "content_exts": non_empty_lines(session_state.get("option_content_exts", "")),
        "pii_scan": session_state.get("option_pii_scan", False),
        "pii_max_bytes": session_state.get("option_pii_max_bytes"),
        "pii_max_size_kb": session_state.get("option_pii_max_size_kb"),
        "pii_max_matches": session_state.get("option_pii_max_matches"),
        "pii_exts": non_empty_lines(session_state.get("option_pii_exts", "")),
        "pii_mask": session_state.get("option_pii_mask", False),
        "pii_store_sample": session_state.get("option_pii_store_sample", False),
        "pii_context_keywords": session_state.get("option_pii_context_keywords", False),
        "excludes": non_empty_lines(session_state.get("option_excludes_text", "")),
        "output_path": session_state.get("option_output_path"),
        "kafka_enabled": session_state.get("option_kafka_enabled", False),
        "kafka_brokers": session_state.get("option_kafka_brokers", ""),
        "kafka_topic": session_state.get("option_kafka_topic", ""),
        "kafka_client_id": session_state.get("option_kafka_client_id", ""),
        "kafka_tls": session_state.get("option_kafka_tls", False),
        "kafka_sasl_enabled": session_state.get("option_kafka_sasl_enabled", False),
        "kafka_username": session_state.get("option_kafka_username", ""),
        "kafka_password_env": session_state.get("option_kafka_password_env", ""),
        "kafka_mask_sensitive": session_state.get("option_kafka_mask_sensitive", True),
    }


def _common_flags(config: dict, *, include_server_type: bool = True) -> list[str]:
    flags: list[str] = []
    if include_server_type:
        flags += ["--server-type", config["server_type"]]
    flags += [
        "--newer-than-h",
        str(config["newer_than_h"]),
        "--max-depth",
        str(config["max_depth"]),
        "--workers",
        str(config["workers"]),
        "--max-size-mb",
        str(config["max_size_mb"]),
        "--out",
        config["output_path"],
    ]
    if config["hash_enabled"]:
        flags.append("--hash")
    if config["follow_symlink"]:
        flags.append("--follow-symlink")
    for item in config["watch_dirs"]:
        flags += ["--watch-dir", item]
    for item in config["excludes"]:
        flags += ["--exclude", item]
    for item in config["allow_mime_prefixes"]:
        flags += ["--allow-mime-prefix", item]
    for item in config["allow_exts"]:
        flags += ["--allow-ext", item]
    for item in config["enable_rules"]:
        flags += ["--enable-rules", item]
    for item in config["disable_rules"]:
        flags += ["--disable-rules", item]
    if config["content_scan"]:
        flags += [
            "--content-scan",
            "--content-max-bytes",
            str(config["content_max_bytes"]),
            "--content-max-size-kb",
            str(config["content_max_size_kb"]),
        ]
        for item in config["content_exts"]:
            flags += ["--content-ext", item]
    if config["pii_scan"]:
        flags += [
            "--pii-scan",
            "--pii-max-bytes",
            str(config["pii_max_bytes"]),
            "--pii-max-size-kb",
            str(config["pii_max_size_kb"]),
            "--pii-max-matches",
            str(config["pii_max_matches"]),
        ]
        for item in config["pii_exts"]:
            flags += ["--pii-ext", item]
        if config["pii_mask"]:
            flags.append("--pii-mask")
        if config["pii_store_sample"]:
            flags.append("--pii-store-sample")
        if config["pii_context_keywords"]:
            flags.append("--pii-context-keywords")
    if config["kafka_enabled"]:
        flags.append("--kafka-enabled")
        if config["kafka_brokers"]:
            flags += ["--kafka-brokers", config["kafka_brokers"]]
        if config["kafka_topic"]:
            flags += ["--kafka-topic", config["kafka_topic"]]
        if config["kafka_client_id"]:
            flags += ["--kafka-client-id", config["kafka_client_id"]]
        if config["kafka_tls"]:
            flags.append("--kafka-tls")
        if config["kafka_sasl_enabled"]:
            flags.append("--kafka-sasl-enabled")
        if config["kafka_username"]:
            flags += ["--kafka-username", config["kafka_username"]]
        if config["kafka_password_env"]:
            flags += ["--kafka-password-env", config["kafka_password_env"]]
        if config["kafka_mask_sensitive"]:
            flags.append("--kafka-mask-sensitive")
    return flags


def build_command(config: dict) -> str:
    cmd = ["./detectbot_linux_amd64_v1_1_3", "--scan"]
    common = _common_flags(config, include_server_type=False)
    if config["server_type"] == "nginx":
        if config["nginx_input_mode"] == "Dump File Path" and config["nginx_dump_path"]:
            cmd += ["--server-type", "nginx", "--nginx-dump", config["nginx_dump_path"]]
        elif config["nginx_input_mode"] == "Pipe Command":
            return (
                "nginx -T 2>&1 | ./detectbot_linux_amd64_v1_1_3 --scan --server-type nginx --nginx-dump - "
                + " ".join(shlex.quote(part) for part in common)
            )
    elif config["server_type"] == "apache":
        if config["apache_input_mode"] == "Dump File Path" and config["apache_dump_path"]:
            cmd += ["--server-type", "apache", "--apache-dump", config["apache_dump_path"]]
        elif config["apache_input_mode"] == "Pipe Command":
            return (
                "apachectl -S 2>&1 | ./detectbot_linux_amd64_v1_1_3 --scan --server-type apache --apache-dump - "
                + " ".join(shlex.quote(part) for part in common)
            )
    else:
        cmd += ["--server-type", "manual"]
    cmd += common
    return " ".join(shlex.quote(part) for part in cmd)


def build_config_payload(config: dict) -> dict:
    kafka_brokers = [item.strip() for item in config["kafka_brokers"].split(",") if item.strip()]
    return {
        "server_type": config["server_type"],
        "scan": True,
        "newer_than_h": config["newer_than_h"],
        "max_depth": config["max_depth"],
        "workers": config["workers"],
        "follow_symlink": config["follow_symlink"],
        "max_size_mb": config["max_size_mb"],
        "hash": config["hash_enabled"],
        "watch_dir": config["watch_dirs"],
        "exclude": config["excludes"],
        "allow_mime_prefix": config["allow_mime_prefixes"],
        "allow_ext": config["allow_exts"],
        "enable_rules": config["enable_rules"],
        "disable_rules": config["disable_rules"],
        "content_scan": config["content_scan"],
        "content_max_bytes": config["content_max_bytes"] if config["content_scan"] else 0,
        "content_max_size_kb": config["content_max_size_kb"] if config["content_scan"] else 0,
        "content_ext": config["content_exts"] if config["content_scan"] else [],
        "pii_scan": config["pii_scan"],
        "pii_max_bytes": config["pii_max_bytes"] if config["pii_scan"] else 0,
        "pii_max_size_kb": config["pii_max_size_kb"] if config["pii_scan"] else 0,
        "pii_max_matches": config["pii_max_matches"] if config["pii_scan"] else 0,
        "pii_ext": config["pii_exts"] if config["pii_scan"] else [],
        "pii_mask": config["pii_mask"] if config["pii_scan"] else False,
        "pii_store_sample": config["pii_store_sample"] if config["pii_scan"] else False,
        "pii_context_keywords": config["pii_context_keywords"] if config["pii_scan"] else False,
        "out": config["output_path"],
        "kafka": {
            "enabled": config["kafka_enabled"],
            "brokers": kafka_brokers if config["kafka_enabled"] else [],
            "topic": config["kafka_topic"],
            "client_id": config["kafka_client_id"],
            "tls": config["kafka_tls"] if config["kafka_enabled"] else False,
            "sasl_enabled": config["kafka_sasl_enabled"] if config["kafka_enabled"] else False,
            "username": config["kafka_username"] if config["kafka_enabled"] else "",
            "password_env": config["kafka_password_env"] if config["kafka_enabled"] else "",
            "mask_sensitive": config["kafka_mask_sensitive"] if config["kafka_enabled"] else False,
        },
    }


def build_notes(config: dict) -> list[str]:
    notes: list[str] = []
    if config["newer_than_h"] and int(config["newer_than_h"]) <= 24:
        notes.append("최근 변경 파일 중심으로 점검하므로 운영 영향이 비교적 적습니다.")
    else:
        notes.append("점검 범위가 넓은 편이므로 운영 환경 적용 전 수행 시간을 확인하는 것이 좋습니다.")
    if config["hash_enabled"]:
        notes.append("해시 계산이 활성화되어 있어 I/O와 점검 시간이 늘어날 수 있습니다.")
    if config["content_scan"]:
        notes.append("본문 기반 민감정보 탐지를 위해 Content Scan이 활성화되어 있습니다.")
    if config["pii_scan"]:
        notes.append("PII 탐지가 활성화되어 있습니다. 마스킹과 샘플 저장 설정을 함께 검토하세요.")
    if config["kafka_enabled"]:
        notes.append("Kafka 전송이 활성화되어 있습니다. 적용 전 topic 권한, TLS, SASL 설정을 확인하세요.")
    return notes


def dumps_json(payload: dict) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2)
