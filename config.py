# config.py

TARGETS = [
    ("demo.pysnmp.com", 161, "1.3.6.1.2.1.1.1.0", "public"),
    ("demo.pysnmp.com", 161, "1.3.6.1.2.1.1.5.0", "public"),
    ("demo.pysnmp.com", 161, "1.3.6.1.2.1.6.9.0", "public"),
    ("demo.pysnmp.com", 161, "1.3.6.1.2.1.2.2.1.10.1", "public"),
    ("demo.pysnmp.com", 161, "1.3.6.1.2.1.2.2.1.16.1", "public"),
]

DB_NAME = "z_net_satut.db"
SCAN_INTERVAL = 10

# 보안 임계치 설정 (Delta 값 기준)
THRESHOLD = {
    "TCP Sessions": 50,      # 10초 내 세션이 50개 이상 증가 시
    "In_Traffic": 1000000,   # 10초 내 1MB 이상 수신 시 (단위: Octets/Bytes)
    "Out_Traffic": 1000000,  # 10초 내 1MB 이상 송신 시
}