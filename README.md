# Z-Net_Satut (Z-VulnScan Network Status Monitor)

**Z-Net_Satut**은 Z-VulnScan 에코시스템의 네트워크 가시성 확보 및 이상 징후 탐지를 담당하는 실시간 보안 관제 솔루션입니다. 비동기 SNMP 수집 엔진과 지능형 분석 로직을 결합하여 인프라의 위협을 실시간으로 시각화합니다.

## 🚀 Key Features

### 1. 지능형 보안 인텔리전스 (SecOps Intelligence)
* **Dual-Layer Detection**: 설정된 절대 임계치(`THRESHOLD`) 돌파 감지 및 과거 이력 데이터를 분석하여 평소보다 급증하는 **동적 스파이크(Spike) 탐지** 기능을 제공합니다.
* **Contextual Alerting**: 침해 사고 시나리오에 기반한 전문적인 보안 알림 메시지를 통해 관제 요원의 신속한 의사결정을 돕습니다.

### 2. 고성능 비동기 모니터링 엔진
* **Async SNMP Engine**: `asyncio` 기반 설계로 수많은 네트워크 장비의 지표를 지연 없이 동시에 수집합니다.
* **Dynamic Interface Mapping**: 장비 연결 시 자동으로 인터페이스를 탐색(Walk)하여 활성화된 포트의 트래픽을 즉시 모니터링 대상에 추가합니다.

### 3. 실무 중심의 데이터 시각화
* **Adaptive Visualization**: 데이터 크기에 따라 B, KB, MB, GB 등으로 단위를 자동 변환하여 가독성을 극대화합니다.
* **Real-time Time-series Charts**: Unix 타임스탬프가 아닌 **실제 시간(HH:MM:SS)** 기반의 가로축 그래프를 지원하여 사고 발생 시점을 정확히 추적합니다.

### 4. 카오스 시뮬레이터 (Chaos Simulator)
* **Real-world Mimicry**: 가우시안 노이즈(Jitter)와 랜덤 버스트(Burst)를 포함하여 실제 환경과 흡사한 트래픽 패턴을 생성합니다.
* **Monotonic Counter Simulation**: 32비트 카운터의 Wrap-around(회전) 현상을 완벽히 모사하여 분석 로직의 신뢰성을 검증합니다.

## 🛠 Tech Stack
* **Language**: Python 3.12+
* **GUI Framework**: PySide6 (Qt for Python)
* **Visualization**: PyQtGraph
* **Protocols**: SNMP v1 / v2c (via PySNMP-lextudio)
* **Database**: SQLite (Local Metric Logging)

## 📂 Project Structure
* `main.py`: 애플리케이션 진입점
* `gui.py`: 메인 대시보드 UI 및 실시간 그래프 로직
* `snmp_engine.py`: 비동기 SNMP 수집 및 분석 엔진
* `simulator/`: 실무 환경 모사를 위한 에이전트 및 카오스 엔진
* `config.py`: 탐지 임계치 및 타겟 장비 설정
* `library.py`: OID 정의 및 보안 메시지 데이터베이스

## 🚦 Quick Start

1. **에이전트 시뮬레이터 실행 (테스트용)**
    ```bash
   python simulator/snmp_agent_sim.py
    ```
2. **모니터링 대시보드 실행**
    ```bash
    python main.py
    ```
---
본 프로젝트는 Z-VulnScan 제품군의 네트워크 보안 레이어를 담당하며, 지속적인 업데이트를 통해 더욱 정교한 탐지 알고리즘을 제공할 예정입니다.