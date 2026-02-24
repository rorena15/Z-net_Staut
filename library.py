OID_LIBRARY = {
    # --- [System & Availability] ---
    "1.3.6.1.2.1.1.1.0": {"name": "SysDescr", "category": "System"},
    "1.3.6.1.2.1.1.3.0": {
        "name": "SysUpTime", 
        "category": "Availability",
        "alert_context": "장비 재부팅 감지! 비인가 재시작 여부를 확인하십시오."
    },
    "1.3.6.1.2.1.1.5.0": {"name": "SysName", "category": "System"},

    # --- [Security Metrics] ---
    "1.3.6.1.2.1.6.9.0": {
        "name": "TCP Sessions", 
        "category": "Security",
        "alert_context": "TCP 세션 급증! DDoS 공격 또는 포트 스캐닝 징후입니다."
    },

    # --- [Traffic Metrics] ---
    "1.3.6.1.2.1.2.2.1.10": {
        "name": "In_Traffic", 
        "category": "Traffic",
        "alert_context": "수신 트래픽 임계치 초과! 대량 데이터 유입 중."
    },
    "1.3.6.1.2.1.2.2.1.16": {
        "name": "Out_Traffic", 
        "category": "Traffic",
        "alert_context": "송신 트래픽 임계치 초과! 내부 데이터 외부 유출 가능성 조사 필요."
    },
    
    # --- [Private OID: Cisco 예시] ---
    "1.3.6.1.4.1.9.9.43.1.1.1.0": {
        "name": "Cisco_Config_Change", 
        "category": "Security",
        "alert_context": "장비 설정 변경 감지! 관리자 권한 도용 여부를 즉시 확인하십시오."
    }
}

def get_oid_info(oid):
    if oid in OID_LIBRARY:
        return OID_LIBRARY[oid]
    for prefix, info in OID_LIBRARY.items():
        if oid.startswith(prefix):
            index_part = oid[len(prefix):]
            new_info = info.copy()
            new_info['name'] = f"{info['name']}{index_part}"
            return new_info
    return {"name": oid, "category": "Unknown"}