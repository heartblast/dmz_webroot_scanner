# DetectBot Portal

DetectBot Portal은 기존 `streamlit_app`와 별도로 운영 흐름 중심으로 구성한 Streamlit 기반 포털입니다.

## 역할

- 서버 인벤토리 관리
- 스캔 리포트 추적 적재
- 개별 탐지 결과 검색 및 조회
- 서버/스캔이력 선택 기반 탐지결과 상세 해석
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
- `detectbot_portal`: 자산, 스캔 이력, 탐지 결과, 정책을 추적 관리하는 포털 구조
- `detectbot_portal/pages/05_detection_report_viewer.py`: 서버와 스캔 실행을 선택한 뒤 저장된 리포트를 `report_parser` 수준으로 상세 해석하는 운영형 조회 화면

## 2단계 확장 시사점

- 일자별 추이 집계 테이블 추가
- 스캔 결과 비교 리포트
- 조치 상태 / 예외 확인 워크플로우
- 외부 수집 파이프라인 연계
- 사용자 / 권한 관리
