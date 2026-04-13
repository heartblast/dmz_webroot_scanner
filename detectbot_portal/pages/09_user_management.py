from __future__ import annotations

import pandas as pd
import streamlit as st

from auth.rbac import ROLE_ADMIN, ROLE_USER
from auth.service import MIN_PASSWORD_LENGTH, AuthService
from auth.session import AUTH_SESSION_KEY, require_role
from bootstrap import bootstrap_portal
from config.settings import load_settings
from lib.navigation import render_portal_sidebar
from lib.ui import format_timestamp_columns, render_portal_header


st.set_page_config(page_title="DetectBot Portal - User Management", page_icon="UM", layout="wide")

settings = load_settings()
bootstrap_portal(seed_demo_data=False)
current_user = require_role(ROLE_ADMIN)
render_portal_sidebar(settings, current_user)

auth_service = AuthService()


def load_users_df() -> pd.DataFrame:
    users_df = pd.DataFrame(auth_service.list_users())
    if users_df.empty:
        return users_df
    users_df = format_timestamp_columns(users_df, ["created_at", "updated_at"])
    return users_df.sort_values(["role", "username"], ascending=[True, True]).reset_index(drop=True)


def public_users_df(users_df: pd.DataFrame) -> pd.DataFrame:
    if users_df.empty:
        return users_df
    return users_df[
        [
            "username",
            "full_name",
            "department",
            "email",
            "role",
            "is_active",
            "created_at",
            "updated_at",
        ]
    ]


render_portal_header(
    "User Management",
    "포털 사용자 계정을 생성하고, 성명, 소속부서, 이메일, 역할, 활성 상태와 비밀번호를 관리합니다.",
)

st.caption(f"현재 로그인 사용자: `{current_user.get('username')}` ({current_user.get('role')})")

with st.form("create_user_form"):
    st.markdown("### 사용자 생성")
    create_col1, create_col2 = st.columns(2)
    with create_col1:
        new_username = st.text_input("사용자 ID", key="create_username")
        new_full_name = st.text_input("성명", key="create_full_name")
        new_department = st.text_input("소속부서", key="create_department")
        new_email = st.text_input("이메일 주소", key="create_email")
    with create_col2:
        new_password = st.text_input(
            "비밀번호",
            type="password",
            key="create_password",
            help=f"최소 {MIN_PASSWORD_LENGTH}자리이며, 소문자/대문자/숫자/특수문자 중 3종류 이상을 포함해야 합니다.",
        )
        new_role = st.selectbox("역할", options=[ROLE_USER, ROLE_ADMIN], key="create_role")
        new_is_active = st.checkbox("활성 계정", value=True, key="create_is_active")

    create_submitted = st.form_submit_button("사용자 생성", width="stretch")
    if create_submitted:
        try:
            auth_service.create_user(
                username=new_username,
                password=new_password,
                role=new_role,
                is_active=new_is_active,
                full_name=new_full_name,
                department=new_department,
                email=new_email,
            )
            st.success("사용자를 생성했습니다.")
            st.rerun()
        except ValueError as exc:
            st.error(str(exc))
        except Exception as exc:
            st.error(f"사용자 생성에 실패했습니다: {exc}")

users_df = load_users_df()

st.markdown("### 사용자 목록")
if users_df.empty:
    st.info("등록된 사용자가 없습니다.")
else:
    st.dataframe(public_users_df(users_df), hide_index=True, use_container_width=True)

st.markdown("### 사용자 수정")
if users_df.empty:
    st.info("먼저 사용자를 생성하세요.")
else:
    user_ids = users_df["id"].tolist()
    selected_user_id = st.selectbox(
        "수정할 사용자",
        options=user_ids,
        format_func=lambda value: users_df.loc[users_df["id"] == value, "username"].iloc[0],
    )
    selected_user = auth_service.get_user_by_id(selected_user_id)

    if selected_user is None:
        st.warning("선택한 사용자가 더 이상 존재하지 않습니다.")
    else:
        role_options = [ROLE_USER, ROLE_ADMIN]
        role_index = role_options.index(selected_user["role"])
        with st.form("edit_user_form"):
            edit_col1, edit_col2 = st.columns(2)
            with edit_col1:
                st.text_input("사용자 ID", value=selected_user["username"], disabled=True)
                edit_full_name = st.text_input("성명", value=selected_user.get("full_name", ""))
                edit_department = st.text_input("소속부서", value=selected_user.get("department", ""))
                edit_email = st.text_input("이메일 주소", value=selected_user.get("email", ""))
            with edit_col2:
                edit_role = st.selectbox("역할", options=role_options, index=role_index)
                edit_is_active = st.checkbox("활성 계정", value=bool(selected_user["is_active"]))
                reset_password = st.text_input(
                    "새 비밀번호",
                    type="password",
                    help="현재 비밀번호를 유지하려면 비워두세요.",
                )

            submitted = st.form_submit_button("변경사항 저장", width="stretch")
            if submitted:
                try:
                    if selected_user_id == current_user.get("id") and not edit_is_active:
                        raise ValueError("자기 자신의 계정은 비활성화할 수 없습니다.")
                    if reset_password and len(reset_password) < MIN_PASSWORD_LENGTH:
                        raise ValueError(f"비밀번호는 {MIN_PASSWORD_LENGTH}자 이상이어야 합니다.")

                    updated_user = auth_service.update_user(
                        selected_user_id,
                        role=edit_role,
                        is_active=edit_is_active,
                        full_name=edit_full_name,
                        department=edit_department,
                        email=edit_email,
                    )
                    if reset_password:
                        auth_service.reset_password(selected_user_id, reset_password)

                    if selected_user_id == current_user.get("id"):
                        st.session_state[AUTH_SESSION_KEY] = {
                            "id": updated_user["id"],
                            "username": updated_user["username"],
                            "role": updated_user["role"],
                        }

                    st.success("사용자 정보를 수정했습니다.")
                    st.rerun()
                except ValueError as exc:
                    st.error(str(exc))
                except Exception as exc:
                    st.error(f"사용자 수정에 실패했습니다: {exc}")
