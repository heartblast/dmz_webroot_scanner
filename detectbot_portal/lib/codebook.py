"""
Code dictionary helpers for DetectBot Portal.
"""

REASON_MEANINGS = {
    "mime_not_in_allowlist": "허용 MIME 정책에 없는 파일",
    "ext_not_in_allowlist": "허용 확장자 정책에 없는 파일",
    "high_risk_extension": "실행·압축·스크립트 계열의 고위험 확장자 파일",
    "large_file": "비정상 반출 의심이 가능한 대용량 파일",
    "large_file_in_web_path": "웹 경로 내 비정상 반출 의심 대용량 파일",
    "mime_ext_mismatch": "확장자와 실제 파일 형식이 서로 일치하지 않음",
    "ext_mime_mismatch_image": "이미지 확장자와 실제 파일 형식이 일치하지 않음",
    "ext_mime_mismatch_archive": "압축 확장자와 실제 파일 형식이 일치하지 않음",
    "recently_modified": "최근 변경된 파일로 우선 확인 필요",
    "resident_registration_number": "주민등록번호 포함 가능성",
    "foreigner_registration_number": "외국인등록번호 포함 가능성",
    "passport_number": "여권번호 포함 가능성",
    "drivers_license": "운전면허번호 포함 가능성",
    "credit_card": "신용카드번호 포함 가능성",
    "bank_account": "계좌번호 포함 가능성",
    "mobile_phone": "휴대전화번호 포함 가능성",
    "email": "이메일 주소 등 식별정보 포함 가능성",
    "email_address": "이메일 주소 등 식별정보 포함 가능성",
    "birth_date": "생년월일 정보 포함 가능성",
    "secret_patterns": "인증정보 또는 비밀값 포함 가능성",
    "jdbc_connection_string": "DB 접속 정보가 포함된 설정 흔적",
    "private_key_material": "개인키·비밀키 포함 가능성",
}

PATTERN_MEANINGS = {
    "jdbc_url_generic": "DB 접속 정보가 포함된 설정 흔적",
    "connection_jdbc_url": "DB 접속 정보가 포함된 설정 흔적",
    "connection_redis_uri": "Redis 접속 정보가 포함된 설정 흔적",
    "connection_mongodb_uri": "MongoDB 접속 정보가 포함된 설정 흔적",
    "connection_postgresql_uri": "PostgreSQL 접속 정보가 포함된 설정 흔적",
    "connection_mysql_uri": "MySQL 접속 정보가 포함된 설정 흔적",
    "connection_ldap_uri": "LDAP 접속 정보가 포함된 설정 흔적",
    "connection_smtp_uri": "SMTP 서버 접속 정보가 포함된 설정 흔적",
    "connection_s3_endpoint": "클라우드 저장소 접속 설정 흔적",
    "password_generic": "인증정보 또는 비밀값 포함 가능성",
    "secret_generic": "비밀정보 또는 민감 설정값 포함 가능성",
    "token_generic": "토큰 정보 포함 가능성",
    "credential_password": "비밀번호 값이 포함된 설정 흔적",
    "credential_username": "사용자 계정명이 포함된 설정 흔적",
    "credential_db_user": "DB 계정명이 포함된 설정 흔적",
    "credential_db_password": "DB 비밀번호가 포함된 설정 흔적",
    "credential_bind_dn": "LDAP 바인드 계정 정보 포함 가능성",
    "credential_bind_password": "LDAP 바인드 비밀번호 포함 가능성",
    "credential_access_key": "접근키가 포함된 설정 흔적",
    "credential_secret_key": "비밀키가 포함된 설정 흔적",
    "credential_api_key": "API 키가 포함된 설정 흔적",
    "credential_client_secret": "클라이언트 비밀값이 포함된 설정 흔적",
    "credential_token": "인증 토큰이 포함된 설정 흔적",
    "credential_access_token": "접근 토큰이 포함된 설정 흔적",
    "credential_refresh_token": "갱신 토큰이 포함된 설정 흔적",
    "private_key": "개인키·비밀키 포함 가능성",
    "private_key_rsa": "RSA 개인키 포함 가능성",
    "private_key_openssh": "OpenSSH 개인키 포함 가능성",
    "private_key_generic": "개인키 블록 포함 가능성",
    "private_key_ec": "EC 개인키 포함 가능성",
    "private_key_dsa": "DSA 개인키 포함 가능성",
    "private_key_pgp": "PGP 개인키 포함 가능성",
    "aws_access_key": "클라우드 접근키 포함 가능성",
    "internal_endpoint_private_ip": "내부망 IP 정보가 노출된 설정 흔적",
    "internal_endpoint_domain": "내부 도메인 정보가 노출된 설정 흔적",
    "combo_jdbc_with_credentials": "DB 접속 정보와 계정정보가 함께 포함됨",
    "combo_datasource_with_credentials": "데이터소스 계정정보가 함께 포함된 설정",
    "combo_redis_with_password": "Redis 접속 정보와 비밀번호가 함께 포함됨",
    "combo_s3_with_keys": "클라우드 접근키와 비밀키가 함께 포함됨",
    "combo_ldap_with_credentials": "LDAP 계정정보와 비밀번호가 함께 포함됨",
    "resident_registration_number": "주민등록번호 포함 가능성",
    "foreigner_registration_number": "외국인등록번호 포함 가능성",
    "passport_number": "여권번호 포함 가능성",
    "drivers_license": "운전면허번호 포함 가능성",
    "credit_card": "신용카드번호 포함 가능성",
    "bank_account": "계좌번호 포함 가능성",
    "mobile_phone": "휴대전화번호 포함 가능성",
    "email": "이메일 주소 등 식별정보 포함 가능성",
    "email_address": "이메일 주소 등 식별정보 포함 가능성",
    "birth_date": "생년월일 정보 포함 가능성",
}

PREFIX_MEANINGS = {
    "connection_": "시스템 또는 서비스 접속 정보가 포함된 설정 흔적",
    "credential_": "인증정보 또는 비밀값 포함 가능성",
    "private_key_": "개인키·비밀키 포함 가능성",
    "combo_": "접속 정보와 인증정보가 함께 포함된 고위험 설정",
    "internal_endpoint_": "내부 시스템 정보가 노출된 설정 흔적",
}


def _lookup(code, mapping, fallback_prefix):
    cleaned = (code or "").strip()
    if not cleaned:
        return fallback_prefix
    if cleaned in mapping:
        return mapping[cleaned]
    for prefix, meaning in PREFIX_MEANINGS.items():
        if cleaned.startswith(prefix):
            return meaning
    return f"{fallback_prefix} ({cleaned})"


def get_reason_meaning(reason_code):
    return _lookup(reason_code, REASON_MEANINGS, "정의되지 않은 탐지 코드")


def get_pattern_meaning(pattern_code):
    return _lookup(pattern_code, PATTERN_MEANINGS, "정의되지 않은 패턴")


def iter_code_dictionary_rows():
    for code, meaning in REASON_MEANINGS.items():
        yield ("reason_code", code, meaning, "default")
    for code, meaning in PATTERN_MEANINGS.items():
        yield ("pattern", code, meaning, "default")
