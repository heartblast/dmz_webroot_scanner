# DetectBot Portal

DetectBot Portal은 기존 `streamlit_app`의 단일 도구형 UI와 별도로 만든 운영 포털형 Streamlit MVP입니다.

## 역할

- 서버 인벤토리 관리
- 점검 리포트 누적 적재
- 개별 탐지 결과 검색 및 조회
- 정책 / 옵션 관리
- 대시보드 기반 기본 현황 확인

## 실행 방법

1. 의존성 설치

```bash
pip install streamlit duckdb pandas
```

2. 포털 실행

```bash
streamlit run detectbot_portal/app.py
```

3. DuckDB 파일 위치

```text
detectbot_portal/data/detectbot_portal.duckdb
```

## 기존 `streamlit_app`와 차이

- `streamlit_app`: 단건 옵션 생성, 단건 JSON 해석 중심
- `detectbot_portal`: 자산, 점검 이력, 탐지 결과, 정책을 누적 관리하는 포털형 구조

## 2단계 확장 포인트

- 일자별 추이 집계 테이블 추가
- 점검 결과 비교 리포트
- 조치 상태 / 예외 승인 워크플로우
- 외부 수집 파이프라인 연계
- 사용자 / 권한 관리
