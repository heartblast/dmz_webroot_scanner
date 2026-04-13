from __future__ import annotations

import streamlit as st

from auth.rbac import ROLE_ADMIN, can_access_role
from auth.service import AuthService


AUTH_SESSION_KEY = "auth_user"


def get_current_user() -> dict | None:
    user = st.session_state.get(AUTH_SESSION_KEY)
    return user if isinstance(user, dict) else None


def logout() -> None:
    st.session_state.pop(AUTH_SESSION_KEY, None)


def require_login() -> dict:
    user = get_current_user()
    if user is not None:
        return user

    render_login_form()
    st.stop()


def require_role(role: str) -> dict:
    user = require_login()
    if can_access_role(user.get("role"), role):
        return user

    st.error("관리자만 접근할 수 있습니다.")
    st.stop()


def render_login_form() -> None:
    st.title("DetectBot Portal Login")
    st.caption("계정으로 로그인한 뒤 DetectBot Portal을 사용할 수 있습니다.")

    auth_service = AuthService()
    with st.form("detectbot_login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login", width="stretch")

    if submitted:
        user = auth_service.authenticate(username, password)
        if user is None:
            st.error("아이디 또는 비밀번호가 올바르지 않습니다.")
            return
        st.session_state[AUTH_SESSION_KEY] = user
        st.rerun()


def render_auth_sidebar(current_user: dict) -> None:
    st.divider()
    st.caption(f"Signed in as `{current_user.get('username', '-')}` ({current_user.get('role', '-')})")
    if current_user.get("role") == ROLE_ADMIN and AuthService().default_admin_warning_enabled():
        st.warning("기본 관리자 비밀번호를 사용 중입니다. 운영 전 환경변수로 초기 계정을 지정하세요.")
    if st.button("Logout", width="stretch"):
        logout()
        st.rerun()
