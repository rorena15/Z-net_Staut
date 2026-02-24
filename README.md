# 🛡️ Z-Net_Satut (Z-Network Status & Security Sensor)

> **"네트워크의 가용성을 넘어, 보안의 문맥(Context)을 읽다."**

`Z-Net_Satut`은 단순한 트래픽 모니터링을 넘어, 실시간 네트워크 인프라의 이상 징후를 탐지하는 **보안 특화 NMS(Network Management System)**입니다. 
취약점 진단 솔루션인 **Z-VulnScan**과 연동되어, 정적인 보안 진단과 동적인 실시간 관제를 통합하는 보안 생태계의 핵심 센서 역할을 수행합니다.

---

## ✨ Key Features

- **🚀 Real-Time SecOps Monitoring**: SNMP 프로콜을 기반으로 네트워크 장비의 상태를 실시간으로 추적합니다.
- **📊 Delta Analysis Engine**: 누적 데이터가 아닌, 이전 스캔 대비 '변화량(Delta)'을 계산하여 트래픽 폭증 및 세션 급증 등 공격 징후를 즉각 식별합니다.
- **🔍 Auto-Interface Discovery (Walk)**: 장비의 모든 네트워크 인터페이스를 자동으로 탐색하여 누락 없는 전수 관제를 실현합니다.
- **🧬 Z-VulnScan Ecosystem**: 취약점이 발견된 자산에 대해 집중 모니터링을 수행하는 능동형 보안 시너지를 제공합니다.
- **🗃️ Persistent Logging**: SQLite를 내장하여 가벼우면서도 강력한 데이터 축적 기능을 제공, 사후 포렌식 및 트렌드 분석을 지원합니다.

---

## 🛠️ Tech Stack

- **Language**: Python 3.12+
- **Library**: `pysnmp` (Asynchronous Engine), `aiohttp`
- **Database**: SQLite 3
- **Architecture**: AsyncIO 기반의 고성능 비동기 스캔 구조

---

## 🏗️ Architecture



1. **Manager**: `Z-Net_Satut` 엔진이 주기적으로 SNMP Get/Next 요청을 전송.
2. **Agent**: 네트워크 장비(서버, 스위치, 공유기 등)가 실시간 OID 데이터를 응답.
3. **Analysis**: 엔진이 수집된 데이터를 해석하고 임계치(Threshold)와 비교하여 경고 발생.
4. **Storage**: 모든 변화 수치는 DB에 기록되어 추후 시각화 및 리포트의 근거가 됨.

---

## 📈 Roadmap: The Power of OID Library

`Z-Net_Satut`의 핵심 경쟁력은 방대한 OID 라이브러리 구축에 있습니다.

- [ ] **Vendor-Specific MIBs**: Cisco, Juniper, HP 등 주요 벤더별 Private OID DB 구축.
- [ ] **Anomaly Detection AI**: 축적된 OID 데이터를 바탕으로 평상시 트래픽 패턴을 학습, 비정상 패턴 자동 감지.
- [ ] **Security Dashboard**: 수집된 데이터를 한눈에 파악할 수 있는 웹 기반 보안 관제 센터(SOC) 화면 구현.
- [ ] **Auto-Mitigation**: 이상 징후 감지 시 자동으로 ACL(Access Control List) 설정을 제안하거나 차단 로직 연동.

---

## 🚀 Getting Started

```bash
# Repository Clone
git clone [https://github.com/rorena15/Z-net_Staut.git](https://github.com/rorena15/Z-net_Staut.git)

# Install Dependencies
pip install pysnmp aiohttp

# Run Monitor
python main.py