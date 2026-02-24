# simulator/chaos_simulator.py 수정
import time

def get_simulated_value(oid, start_time):
    elapsed = int(time.time() - start_time)
    oid_str = str(oid)
    
    # 1. TCP Sessions (OID에 1.6.9.0이 포함되면 무조건 매칭)
    if "1.6.9.0" in oid_str:
        # 실행 즉시 임계치(50)를 넘도록 100부터 시작하여 폭증 시뮬레이션
        return 100 + (elapsed * 20)
    
    # 2. Traffic (10번 수신, 16번 송신)
    if "1.2.2.1.10" in oid_str or "1.2.2.1.16" in oid_str:
        return 2000000 + (elapsed * 500000)
        
    # 3. SysDescr 등 기본값
    if "1.3.6.1.2.1.1.1.0" in oid_str:
        return 0 # 문자열 응답은 시뮬레이터에서 처리
        
    return 10 # 기본값