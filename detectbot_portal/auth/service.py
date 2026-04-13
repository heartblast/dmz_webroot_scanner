from __future__ import annotations

import os
import json
from datetime import datetime, timedelta, timezone

import bcrypt
from sqlalchemy import func, select

from auth.rbac import ROLE_ADMIN, VALID_ROLES, normalize_role
from db.base import utcnow
from db.factory import session_scope
from db.models import AppSetting, PortalUser


ADMIN_USERNAME_ENV = "DETECTBOT_ADMIN_USERNAME"
ADMIN_PASSWORD_ENV = "DETECTBOT_ADMIN_PASSWORD"
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin123!"
DEFAULT_ADMIN_WARNING_KEY = "auth_default_admin_credentials"
LOGIN_FAILURE_PREFIX = "auth_login_failure"
MAX_FAILED_LOGIN_ATTEMPTS = 5
LOGIN_LOCK_MINUTES = 5
MIN_PASSWORD_LENGTH = 10


class AuthService:
    def hash_password(self, password: str) -> str:
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    def verify_password(self, password: str, password_hash: str) -> bool:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))

    def authenticate(self, username: str, password: str) -> dict | None:
        username = username.strip()
        if not username or not password:
            return None

        with session_scope() as session:
            if self._is_login_locked(session, username):
                return None
            user = session.scalar(select(PortalUser).where(PortalUser.username == username))
            if user is None or not user.is_active:
                self._record_failed_login(session, username)
                return None
            if not self.verify_password(password, user.password_hash):
                self._record_failed_login(session, username)
                return None
            self._clear_failed_login(session, username)
            return self.user_to_session_dict(user)

    def list_users(self) -> list[dict]:
        with session_scope() as session:
            users = session.scalars(select(PortalUser).order_by(PortalUser.username)).all()
            return [self.user_to_public_dict(user) for user in users]

    def get_user_by_username(self, username: str) -> dict | None:
        username = username.strip()
        if not username:
            return None
        with session_scope() as session:
            user = session.scalar(select(PortalUser).where(PortalUser.username == username))
            return self.user_to_public_dict(user) if user is not None else None

    def get_user_by_id(self, user_id: str) -> dict | None:
        user_id = str(user_id or "").strip()
        if not user_id:
            return None
        with session_scope() as session:
            user = session.scalar(select(PortalUser).where(PortalUser.id == user_id))
            return self.user_to_public_dict(user) if user is not None else None

    def create_user(
        self,
        username: str,
        password: str,
        role: str,
        is_active: bool = True,
        full_name: str = "",
        department: str = "",
        email: str = "",
    ) -> dict:
        username = username.strip()
        self._validate_username(username)
        self._validate_password(password)
        role = self._validate_role(role)
        email = self._validate_email(email)

        with session_scope() as session:
            existing = session.scalar(select(PortalUser).where(PortalUser.username == username))
            if existing is not None:
                raise ValueError("Username already exists.")

            user = PortalUser(
                username=username,
                full_name=full_name.strip(),
                department=department.strip(),
                email=email,
                password_hash=self.hash_password(password),
                role=role,
                is_active=bool(is_active),
                created_at=utcnow(),
                updated_at=utcnow(),
            )
            session.add(user)
            session.flush()
            return self.user_to_public_dict(user)

    def update_user(
        self,
        user_id: str,
        role: str,
        is_active: bool,
        full_name: str = "",
        department: str = "",
        email: str = "",
    ) -> dict:
        role = self._validate_role(role)
        is_active = bool(is_active)
        email = self._validate_email(email)

        with session_scope() as session:
            user = session.scalar(select(PortalUser).where(PortalUser.id == user_id))
            if user is None:
                raise ValueError("User not found.")

            active_admins = self._count_active_admins_in_session(session)
            user_is_active_admin = user.role == ROLE_ADMIN and user.is_active
            requested_active_admin = role == ROLE_ADMIN and is_active
            if active_admins <= 1 and user_is_active_admin and not requested_active_admin:
                raise ValueError("At least one active admin account is required.")

            user.role = role
            user.is_active = is_active
            user.full_name = full_name.strip()
            user.department = department.strip()
            user.email = email
            user.updated_at = utcnow()
            session.flush()
            return self.user_to_public_dict(user)

    def reset_password(self, user_id: str, new_password: str) -> dict:
        self._validate_password(new_password)
        with session_scope() as session:
            user = session.scalar(select(PortalUser).where(PortalUser.id == user_id))
            if user is None:
                raise ValueError("User not found.")
            user.password_hash = self.hash_password(new_password)
            user.updated_at = utcnow()
            session.flush()
            return self.user_to_public_dict(user)

    def count_active_admins(self) -> int:
        with session_scope() as session:
            return self._count_active_admins_in_session(session)

    def ensure_initial_admin(self) -> dict:
        with session_scope() as session:
            admin_count = session.scalar(
                select(func.count())
                .select_from(PortalUser)
                .where(PortalUser.role == ROLE_ADMIN, PortalUser.is_active.is_(True))
            )
            if admin_count:
                setting = session.scalar(
                    select(AppSetting).where(AppSetting.setting_key == DEFAULT_ADMIN_WARNING_KEY)
                )
                warning_enabled = str(setting.setting_value if setting else "").lower() == "true"
                return {"created": False, "default_credentials": warning_enabled}

            env_username = os.getenv(ADMIN_USERNAME_ENV, "").strip()
            env_password = os.getenv(ADMIN_PASSWORD_ENV, "")
            if not env_username or not env_password:
                raise RuntimeError(
                    f"No admin account exists. Set {ADMIN_USERNAME_ENV} and {ADMIN_PASSWORD_ENV} "
                    "to create the initial admin account."
                )

            username = env_username
            password = env_password
            self._validate_password(password)

            user = session.scalar(select(PortalUser).where(PortalUser.username == username))
            if user is None:
                user = PortalUser(
                    username=username,
                    full_name="",
                    department="",
                    email="",
                    password_hash=self.hash_password(password),
                    role=ROLE_ADMIN,
                    is_active=True,
                    created_at=utcnow(),
                    updated_at=utcnow(),
                )
                session.add(user)
            else:
                user.password_hash = self.hash_password(password)
                user.role = ROLE_ADMIN
                user.is_active = True
                user.full_name = user.full_name or ""
                user.department = user.department or ""
                user.email = user.email or ""
                user.updated_at = utcnow()

            self._set_app_setting(session, DEFAULT_ADMIN_WARNING_KEY, "false")
            return {"created": True, "default_credentials": False}

    def default_admin_warning_enabled(self) -> bool:
        with session_scope() as session:
            setting = session.scalar(
                select(AppSetting).where(AppSetting.setting_key == DEFAULT_ADMIN_WARNING_KEY)
            )
            return str(setting.setting_value if setting else "").lower() == "true"

    def user_to_session_dict(self, user: PortalUser) -> dict:
        return {
            "id": user.id,
            "username": user.username,
            "role": normalize_role(user.role),
        }

    def user_to_public_dict(self, user: PortalUser) -> dict:
        return {
            "id": user.id,
            "username": user.username,
            "full_name": user.full_name or "",
            "department": user.department or "",
            "email": user.email or "",
            "role": normalize_role(user.role),
            "is_active": bool(user.is_active),
            "created_at": user.created_at,
            "updated_at": user.updated_at,
        }

    def _validate_username(self, username: str) -> None:
        if not username:
            raise ValueError("Username is required.")

    def _validate_password(self, password: str) -> None:
        password = password or ""
        if len(password) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
        checks = [
            any(char.islower() for char in password),
            any(char.isupper() for char in password),
            any(char.isdigit() for char in password),
            any(not char.isalnum() for char in password),
        ]
        if sum(checks) < 3:
            raise ValueError(
                "Password must include at least three of: lowercase, uppercase, digit, special character."
            )

    def _validate_email(self, email: str) -> str:
        normalized = str(email or "").strip()
        if normalized and ("@" not in normalized or normalized.startswith("@") or normalized.endswith("@")):
            raise ValueError("Invalid email address.")
        return normalized

    def _validate_role(self, role: str) -> str:
        normalized = str(role or "").strip().lower()
        if normalized not in VALID_ROLES:
            raise ValueError("Invalid role.")
        return normalized

    def _count_active_admins_in_session(self, session) -> int:
        return int(
            session.scalar(
                select(func.count())
                .select_from(PortalUser)
                .where(PortalUser.role == ROLE_ADMIN, PortalUser.is_active.is_(True))
            )
            or 0
        )

    def _set_app_setting(self, session, key: str, value: str) -> None:
        setting = session.scalar(select(AppSetting).where(AppSetting.setting_key == key))
        if setting is None:
            session.add(
                AppSetting(
                    setting_key=key,
                    setting_value=value,
                    created_at=utcnow(),
                    updated_at=utcnow(),
                )
            )
            return
        setting.setting_value = value
        setting.updated_at = utcnow()

    def _login_failure_key(self, username: str) -> str:
        return f"{LOGIN_FAILURE_PREFIX}:{username.strip().lower()}"

    def _load_login_failure_state(self, session, username: str) -> dict:
        setting = session.scalar(
            select(AppSetting).where(AppSetting.setting_key == self._login_failure_key(username))
        )
        if setting is None or not setting.setting_value:
            return {"count": 0, "locked_until": ""}
        try:
            state = json.loads(setting.setting_value)
        except Exception:
            return {"count": 0, "locked_until": ""}
        return state if isinstance(state, dict) else {"count": 0, "locked_until": ""}

    def _is_login_locked(self, session, username: str) -> bool:
        state = self._load_login_failure_state(session, username)
        locked_until = str(state.get("locked_until") or "")
        if not locked_until:
            return False
        try:
            return datetime.fromisoformat(locked_until) > datetime.now(timezone.utc)
        except ValueError:
            return False

    def _record_failed_login(self, session, username: str) -> None:
        state = self._load_login_failure_state(session, username)
        count = int(state.get("count") or 0) + 1
        locked_until = ""
        if count >= MAX_FAILED_LOGIN_ATTEMPTS:
            locked_until = (datetime.now(timezone.utc) + timedelta(minutes=LOGIN_LOCK_MINUTES)).isoformat()
        self._set_app_setting(
            session,
            self._login_failure_key(username),
            json.dumps({"count": count, "locked_until": locked_until}),
        )

    def _clear_failed_login(self, session, username: str) -> None:
        self._set_app_setting(
            session,
            self._login_failure_key(username),
            json.dumps({"count": 0, "locked_until": ""}),
        )
