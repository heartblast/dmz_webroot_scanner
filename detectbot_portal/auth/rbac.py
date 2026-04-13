from __future__ import annotations


ROLE_USER = "user"
ROLE_ADMIN = "admin"
VALID_ROLES = {ROLE_USER, ROLE_ADMIN}

PAGE_PERMISSIONS = {
    "home": {ROLE_USER, ROLE_ADMIN},
    "server_inventory": {ROLE_USER, ROLE_ADMIN},
    "report_upload_history": {ROLE_USER, ROLE_ADMIN},
    "findings": {ROLE_USER, ROLE_ADMIN},
    "scan_policies": {ROLE_USER, ROLE_ADMIN},
    "dashboard": {ROLE_USER, ROLE_ADMIN},
    "policies": {ROLE_USER, ROLE_ADMIN},
    "report_viewer": {ROLE_USER, ROLE_ADMIN},
    "download_detectbot": {ROLE_USER, ROLE_ADMIN},
    "settings": {ROLE_ADMIN},
    "user_management": {ROLE_ADMIN},
    "option_generator": {ROLE_USER, ROLE_ADMIN},
    "scenario_generator": {ROLE_USER, ROLE_ADMIN},
}


def normalize_role(role: str | None) -> str:
    normalized = str(role or "").strip().lower()
    return normalized if normalized in VALID_ROLES else ROLE_USER


def can_access_page(role: str | None, page_key: str) -> bool:
    allowed_roles = PAGE_PERMISSIONS.get(page_key, {ROLE_ADMIN})
    return normalize_role(role) in allowed_roles


def can_access_role(current_role: str | None, required_role: str) -> bool:
    current = normalize_role(current_role)
    required = normalize_role(required_role)
    if required == ROLE_ADMIN:
        return current == ROLE_ADMIN
    return current in {ROLE_USER, ROLE_ADMIN}
