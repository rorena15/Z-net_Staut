# chaos_simulator.py
import time
import random

# 테스트 시나리오 정의
def get_simulated_value(oid, start_time):
    elapsed = int(time.time() - start_time)
    oid_str = str(oid)
    
    # [매칭 강화] 앞뒤 점(.) 유무와 상관없이 '1.6.9.0'이 포함되면 TCP Sessions로 간주
    if "1.6.9.0" in oid_str:
        # 5초 뒤부터 100씩 폭증 (임계치 50 즉시 돌파)
        return 10 + (elapsed * 10) if elapsed > 5 else 10
    
    if "1.2.2.1.10" in oid_str or "1.2.2.1.16" in oid_str:
        return elapsed * 2000000 
        
    return 10 # 매칭 실패 시 고정값 (Delta 0 확인용)
# 실제 에이전트를 띄우는 대신, Z-Net_Satut이 읽을 수 있는 
# "가짜 데이터 주입용 인터페이스" 역할을 하는 코드입니다.