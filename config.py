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
    ("127.0.0.1", 1161, "1.3.6.1.2.1.2.2.1.10.1", "public", "udp"), # 로컬 수신 트래픽
    ("127.0.0.1", 1161, "1.3.6.1.2.1.2.2.1.16.1", "public", "udp"), # 로컬 송신 트래픽
]

DB_NAME = "z_net_satut.db"
SCAN_INTERVAL = 10

# 보안 임계치 설정 (Delta 값 기준)
THRESHOLD = {
    "TCP Sessions": 50,      # 10초 내 세션이 50개 이상 증가 시
    "In_Traffic": 1000000,   # 10초 내 1MB 이상 수신 시 (단위: Octets/Bytes)
    "Out_Traffic": 1000000,  # 10초 내 1MB 이상 송신 시
}