from __future__ import annotations

import json
from pathlib import Path

from db.schema_init import initialize_schema
from services.policy_service import PolicyService
from services.scan_service import ScanService
from services.server_service import ServerService


SAMPLE_REPORT_PATH = Path(__file__).resolve().parent / "samples" / "sample_report_web01.json"


def bootstrap_portal(seed_demo_data: bool = True) -> None:
    initialize_schema()
    if not seed_demo_data:
        return

    policy_service = PolicyService()
    server_service = ServerService()
    scan_service = ScanService()

    policy_id = policy_service.ensure_default_policy()
    servers_df = server_service.list_servers_df(active_only=False)
    if servers_df is None or servers_df.empty:
        server_id = server_service.save_server(
            {
                "server_name": "web-dmz-01",
                "hostname": "web-dmz-01.example.local",
                "ip_address": "10.10.10.21",
                "environment": "prod",
                "zone": "dmz",
                "os_type": "linux",
                "web_server_type": "nginx",
                "service_name": "customer-portal",
                "criticality": "critical",
                "owner_name": "security-ops",
                "upload_enabled": True,
                "is_active": True,
                "notes": "Seeded demo inventory record.",
            }
        )
    else:
        server_id = str(servers_df.iloc[0]["id"])

    if scan_service.list_scan_runs_df(limit=1).empty and SAMPLE_REPORT_PATH.is_file():
        scan_service.ingest_report(
            SAMPLE_REPORT_PATH.read_bytes(),
            SAMPLE_REPORT_PATH.name,
            server_id=server_id,
            policy_id=policy_id,
            input_type="manual_json",
            uploaded_by="seed",
            original_path=str(SAMPLE_REPORT_PATH),
            auto_create_server=False,
        )
