# Streamlit UI ↔ CLI 옵션 매핑

아래 표는 Streamlit 페이지에서 사용자가 입력할 수 있는 항목과 내부적으로 생성되는 CLI 플래그를 대응시킨 것입니다.

| Streamlit 항목 | CLI 플래그 | 비고 |
|---------------|------------|------|
| 서버 유형 | `--server-type` | nginx, apache, manual |
| Nginx 덤프 파일 | `--nginx-dump` | `-`일 경우 stdin |
| Apache 덤프 파일 | `--apache-dump` | |
| 감시 디렉토리 | `--watch-dir` | 반복 가능 |
| 스캔 실행 여부 | `--scan` | boolean |
| 제외 경로 | `--exclude` | 반복 가능 |
| 최대 깊이 | `--max-depth` | int |
| 최근 N시간 | `--newer-than-h` | int |
| 워커 수 | `--workers` | int |
| 해시 | `--hash` | boolean |
| 최대 파일 크기 | `--max-size-mb` | int |
| 심볼릭 링크 | `--follow-symlink` | boolean |
| 허용 MIME prefix | `--allow-mime-prefix` | 반복 가능 |
| 허용 확장자 | `--allow-ext` | 반복 가능 |
| 콘텐츠 스캔 | `--content-scan` | boolean |
| 콘텐츠 최대 바이트 | `--content-max-bytes` | int |
| 콘텐츠 최대 크기 | `--content-max-size-kb` | int |
| 콘텐츠 확장자 | `--content-ext` | 반복 가능 |
| 프리셋 | `--preset` | safe, balanced, deep, handover, offboarding |
| 설정 파일 | `--config` | YAML/JSON 파일 경로 |
| 룰 활성화 | `--enable-rules` | comma/반복 |
| 룰 비활성화 | `--disable-rules` | comma/반복 |
| Kafka 사용 | `--kafka-enabled` | boolean |
| Kafka 브로커 | `--kafka-brokers` | 반복/콤마 |
| Kafka 토픽 | `--kafka-topic` | |
| Kafka 클라이언트 ID | `--kafka-client-id` | |
| Kafka TLS | `--kafka-tls` | boolean |
| Kafka SASL | `--kafka-sasl-enabled` | boolean (stub) |
| Kafka 사용자명 | `--kafka-username` | |
| Kafka 비밀번호 env | `--kafka-password-env` | |
| Kafka 민감정보 마스킹 | `--kafka-mask-sensitive` | boolean |

UI가 생성하는 커맨드는 이 표를 참고하면 수정 없이 그대로 실행할 수 있습니다.