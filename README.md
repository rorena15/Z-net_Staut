# 📋 프로젝트 개발 기술서 (Draft)
## 1. 프로젝트 개요
- 명칭: Z-NetWatch (가제)
- 목표: SNMP 프로토콜과 멀티스레딩 기술을 활용하여 대규모 네트워크 인프라의 상태를 실시간으로 수집, 분석 및 시각화하는 고성능 관제 시스템 구축.
- 핵심 가치: 확장성(Scalability), 실시간성(Real-time), 보안성(Security).

## 2. 주요 기능 요구사항 (Functional Requirements)
- 장비 스캐닝 및 등록: 특정 IP 대역을 스캔하여 SNMP 응답이 있는 장비를 자동으로 탐색 및 등록.
- 실시간 성능 수집: CPU, Memory, Traffic(In/Out), Uptime 등 주요 MIB 데이터 수집.
- 임계치 기반 알림: 트래픽 급증이나 장비 Down 시 즉각적인 Alert 발생 (Slack/Discord 연동).
- 보안 관제: SNMPv3를 기본으로 하여 수집 데이터의 무결성과 기밀성 보장.
- 대시보드: 수집된 시계열 데이터를 그래프로 시각화.

## 3. 기술 스택 (Technical Stack)
- Language: Python 3.x (Z-VulnScan과의 모듈 호환성 고려)
- Concurrency: threading (기존 노하우 활용) + Queue
- Library: PySNMP (SNMP v1/2c/3 지원)
- Database: InfluxDB (시계열 데이터 저장) 또는 SQLite (소규모 프로토타입용)
- Visualization: Grafana (신속한 대시보드 구축) 또는 Streamlit (Python 기반 웹 UI)

# 🛠 시스템 아키텍처 및 상세 설계 기준
## 1. 수집 엔진 구조 (Multi-threading Logic)
- Worker Pool: 고정된 수의 워커 스레드를 유지하여 시스템 리소스 과다 점유 방지.
- Job Queue: 수집 대상 장비 리스트를 큐에 넣고, 워커 스레드가 이를 하나씩 처리.
- Error Handling: 타임아웃 발생 시 해당 장비를 'Unreachable' 상태로 마킹하고 다음 작업 수행 (전체 루프 지연 방지).

## 2. 프로젝트 성공 기준 (Success Criteria)
- 개발 완료 시 아래 기준을 만족하는지 검증합니다.
- 동시 처리량: 최소 50대 이상의 장비에서 데이터를 10초 주기로 수집해도 지연이 없는가?
- 안정성: 특정 장비가 네트워크에서 제거되어도 전체 수집 엔진이 멈추지 않는가?
- 정확성: 수집된 OID 값이 실제 장비의 상태와 일치하는가?
- 보안: SNMPv3 Auth/Priv 설정이 정상적으로 작동하는가?

# 📅 초기 개발 로드맵 (Milestones)
- Phase 1 (기획 및 환경): 개발 기술서 확정 및 SNMP 시뮬레이터(Agent) 환경 구축.
- Phase 2 (엔진 개발): 멀티스레딩 기반의 SNMP Get/Walk 기본 모듈 개발 (Z-VulnScan 로직 이식).
- Phase 3 (데이터 저장): 수집된 데이터를 DB에 정형화하여 저장하는 모듈 연동.
- Phase 4 (시각화 및 알림): 대시보드 구성 및 임계치 알림 로직 구현.
- Phase 5 (최적화): 대량 수집 시 병목 구간 탐색 및 코드 최적화.