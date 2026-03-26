"""
Seed helpers for DetectBot Portal MVP.
"""

from pathlib import Path

from lib.ingest import ingest_report
from lib.repository import fetch_one, save_server, seed_default_policy


SAMPLE_REPORT_PATH = (
    Path(__file__).resolve().parents[1] / "samples" / "sample_report_web01.json"
)


def bootstrap_demo_data():
    policy_id = seed_default_policy()

    server = fetch_one("SELECT id FROM servers LIMIT 1")
    if not server:
        server_id = save_server(
            {
                "server_name": "web-dmz-01",
                "hostname": "web-dmz-01.example.local",
                "ip_address": "10.10.10.21",
                "environment": "prod",
                "zone": "dmz",
                "os_type": "linux",
                "web_server_type": "nginx",
                "service_name": "고객포털",
                "criticality": "critical",
                "owner_name": "보안운영팀",
                "upload_enabled": True,
                "is_active": True,
                "notes": "MVP 시드 데이터",
            }
        )
    else:
        server_id = server["id"]

    has_runs = fetch_one("SELECT COUNT(*) AS count FROM scan_runs")
    if has_runs and has_runs["count"] > 0:
        return

    if SAMPLE_REPORT_PATH.is_file():
        ingest_report(
            SAMPLE_REPORT_PATH.read_bytes(),
            SAMPLE_REPORT_PATH.name,
            server_id=server_id,
            policy_id=policy_id,
            input_type="manual_json",
            uploaded_by="seed",
            original_path=str(SAMPLE_REPORT_PATH),
            auto_create_server=False,
        )
