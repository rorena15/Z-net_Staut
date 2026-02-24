TARGETS = [
    # 기존 기본 정보
    ("demo.pysnmp.com", 161, "1.3.6.1.2.1.1.1.0", "public"), # sysDescr
    ("demo.pysnmp.com", 161, "1.3.6.1.2.1.1.5.0", "public"), # sysName
    
    # 보안 관제용 데이터 (이상 징후 탐지용)
    ("demo.pysnmp.com", 161, "1.3.6.1.2.1.6.9.0", "public"),       # tcpCurrEstab (TCP 연결 수)
    ("demo.pysnmp.com", 161, "1.3.6.1.2.1.2.2.1.10.1", "public"),  # ifInOctets (수신 트래픽)
    ("demo.pysnmp.com", 161, "1.3.6.1.2.1.2.2.1.16.1", "public"),  # ifOutOctets (송신 트래픽)
]

DB_NAME = "z_net_satut.db"
SCAN_INTERVAL = 10