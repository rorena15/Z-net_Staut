TARGETS = [
    # (IP, Port, OID, Community, Protocol)
    # external 테스트 주소 (UDP 사용)
    ("demo.pysnmp.com", 161, "1.3.6.1.2.1.1.1.0", "public", "udp"),
    ("demo.pysnmp.com", 161, "1.3.6.1.2.1.1.5.0", "public", "udp"),
    ("demo.pysnmp.com", 161, "1.3.6.1.2.1.6.9.0", "public", "udp"),
    ("demo.pysnmp.com", 161, "1.3.6.1.2.1.2.2.1.10.1", "public", "udp"),
    ("demo.pysnmp.com", 161, "1.3.6.1.2.1.2.2.1.16.1", "public", "udp"),
    
    # local 테스트 주소 (아까 netstat에서 확인된 TCP 사용)
    ("127.0.0.1", 1161, "1.3.6.1.2.1.1.1.0", "public", "udp"),      # 로컬 장비 설명
    ("127.0.0.1", 1161, "1.3.6.1.2.1.6.9.0", "public", "udp"),      # TCP 세션 감지
]

DB_NAME = "z_net_satut.db"
SCAN_INTERVAL = 10

# 보안 임계치 설정 (Delta 값 기준)
THRESHOLD = {
    # 10초 동안 세션이 1,000개 이상 급증 시 (시뮬레이터가 4,200까지 가므로 적절)
    "TCP Sessions": 1000,      
    # 10초 동안 약 500MB 유입 시 (초당 50MB / 400Mbps 수준)
    # 실무 기가비트 라인에서 '위험' 신호로 간주되는 수치입니다.
    "In_Traffic": 524288000,   
    "Out_Traffic": 524288000,  
    # 0보다 작아지면(시스템 재시작) 즉시 탐지
    "Uptime": 0                  
}