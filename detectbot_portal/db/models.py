from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BIGINT, BOOLEAN, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.base import Base, utcnow


def _uuid() -> str:
    return str(uuid.uuid4())


class ServerInventory(Base):
    __tablename__ = "server_inventory"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    server_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64))
    environment: Mapped[str] = mapped_column(String(32), default="unknown")
    zone: Mapped[str] = mapped_column(String(32), default="unknown")
    os_type: Mapped[str] = mapped_column(String(32), default="unknown")
    os_name: Mapped[str | None] = mapped_column(String(255))
    os_version: Mapped[str | None] = mapped_column(String(255))
    platform: Mapped[str | None] = mapped_column(String(255))
    web_server_type: Mapped[str] = mapped_column(String(32), default="unknown")
    service_name: Mapped[str | None] = mapped_column(String(255))
    criticality: Mapped[str] = mapped_column(String(32), default="medium")
    owner_name: Mapped[str | None] = mapped_column(String(255))
    upload_enabled: Mapped[bool] = mapped_column(BOOLEAN, default=True)
    is_active: Mapped[bool] = mapped_column(BOOLEAN, default=True)
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    scan_jobs: Mapped[list["ScanJob"]] = relationship(
        back_populates="server", cascade="all, delete-orphan"
    )


class ScanPolicy(Base):
    __tablename__ = "scan_policy"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    policy_name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(Text)
    policy_mode: Mapped[str] = mapped_column(String(32), default="balanced")
    policy_version: Mapped[str] = mapped_column(String(64), default="v1")
    allow_mime_json: Mapped[str] = mapped_column(Text, default="[]")
    allow_ext_json: Mapped[str] = mapped_column(Text, default="[]")
    exclude_paths_json: Mapped[str] = mapped_column(Text, default="[]")
    max_depth: Mapped[int] = mapped_column(Integer, default=10)
    newer_than_hours: Mapped[int] = mapped_column(Integer, default=0)
    size_threshold_mb: Mapped[int] = mapped_column(Integer, default=100)
    compute_hash: Mapped[bool] = mapped_column(BOOLEAN, default=False)
    content_scan_enabled: Mapped[bool] = mapped_column(BOOLEAN, default=True)
    content_max_kb: Mapped[int] = mapped_column(Integer, default=1024)
    pii_scan_enabled: Mapped[bool] = mapped_column(BOOLEAN, default=True)
    custom_config_json: Mapped[str | None] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(BOOLEAN, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    scan_jobs: Mapped[list["ScanJob"]] = relationship(back_populates="policy")


class ScanJob(Base):
    __tablename__ = "scan_job"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    server_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("server_inventory.id", ondelete="SET NULL"), index=True
    )
    policy_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("scan_policy.id", ondelete="SET NULL"), index=True
    )
    report_file_name: Mapped[str | None] = mapped_column(String(255))
    report_original_path: Mapped[str | None] = mapped_column(Text)
    report_stored_path: Mapped[str | None] = mapped_column(Text)
    scanner_version: Mapped[str | None] = mapped_column(String(64))
    input_type: Mapped[str | None] = mapped_column(String(64))
    uploaded_by: Mapped[str | None] = mapped_column(String(255))
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    scan_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    scan_finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    host_hostname: Mapped[str | None] = mapped_column(String(255))
    host_primary_ip: Mapped[str | None] = mapped_column(String(64))
    host_os_type: Mapped[str | None] = mapped_column(String(32))
    host_os_name: Mapped[str | None] = mapped_column(String(255))
    host_platform: Mapped[str | None] = mapped_column(String(255))
    latest_for_server: Mapped[bool] = mapped_column(BOOLEAN, default=False, index=True)
    active_rules_json: Mapped[str | None] = mapped_column(Text)
    config_json: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    server: Mapped[ServerInventory | None] = relationship(back_populates="scan_jobs")
    policy: Mapped[ScanPolicy | None] = relationship(back_populates="scan_jobs")
    result_summary: Mapped["ScanResultSummary | None"] = relationship(
        back_populates="scan_job", cascade="all, delete-orphan", uselist=False
    )
    findings: Mapped[list["ScanFinding"]] = relationship(
        back_populates="scan_job", cascade="all, delete-orphan"
    )


class ScanResultSummary(Base):
    __tablename__ = "scan_result_summary"
    __table_args__ = (UniqueConstraint("scan_job_id", name="uq_scan_result_summary_scan_job_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_job_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_job.id", ondelete="CASCADE"), nullable=False
    )
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    roots_count: Mapped[int] = mapped_column(Integer, default=0)
    scanned_files: Mapped[int] = mapped_column(Integer, default=0)
    severity_summary_json: Mapped[str] = mapped_column(Text, default="{}")
    roots_json: Mapped[str] = mapped_column(Text, default="[]")
    raw_summary_json: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    scan_job: Mapped[ScanJob] = relationship(back_populates="result_summary")


class ScanFinding(Base):
    __tablename__ = "scan_finding"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_job_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_job.id", ondelete="CASCADE"), nullable=False, index=True
    )
    server_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("server_inventory.id", ondelete="SET NULL"), index=True
    )
    path: Mapped[str] = mapped_column(Text)
    real_path: Mapped[str | None] = mapped_column(Text)
    root_matched: Mapped[str | None] = mapped_column(Text)
    root_source: Mapped[str | None] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(32), index=True, default="unknown")
    size_bytes: Mapped[int | None] = mapped_column(BIGINT)
    mod_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    perm: Mapped[str | None] = mapped_column(String(64))
    ext: Mapped[str | None] = mapped_column(String(64))
    mime_sniff: Mapped[str | None] = mapped_column(String(255))
    sha256: Mapped[str | None] = mapped_column(String(255))
    url_exposure_heuristic: Mapped[str | None] = mapped_column(String(255))
    reasons_json: Mapped[str] = mapped_column(Text, default="[]")
    matched_patterns_json: Mapped[str] = mapped_column(Text, default="[]")
    evidence_masked_json: Mapped[str] = mapped_column(Text, default="[]")
    content_flags_json: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    scan_job: Mapped[ScanJob] = relationship(back_populates="findings")


class AppSetting(Base):
    __tablename__ = "app_setting"

    setting_key: Mapped[str] = mapped_column(String(255), primary_key=True)
    setting_value: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class PortalUser(Base):
    __tablename__ = "portal_user"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    username: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    full_name: Mapped[str | None] = mapped_column(String(255))
    department: Mapped[str | None] = mapped_column(String(255))
    email: Mapped[str | None] = mapped_column(String(255))
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="user", index=True)
    is_active: Mapped[bool] = mapped_column(BOOLEAN, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
