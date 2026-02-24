# chaos_simulator.py
import time
import random

# 테스트 시나리오 정의
def get_simulated_value(oid, start_time):
    elapsed = int(time.time() - start_time)
    
    # 1. TCP 세션 폭증 시나리오 (30초 뒤 공격 시작)
    if "1.3.6.1.2.1.6.9.0" in oid:
        return 10 + (elapsed * 5) if elapsed > 30 else 10
    
    # 2. 트래픽 과부하 시나리오 (점진적 증가)
    if "1.3.6.1.2.1.2.2.1.10" in oid:
        return elapsed * 2000000  # 10초마다 약 20MB씩 증가
        
    # 3. 장비 재부팅 시나리오 (60초 뒤 가동 시간 초기화)
    if "1.3.6.1.2.1.1.3.0" in oid:
        return 50 if elapsed > 60 else elapsed * 100
        
    return random.randint(1, 100)

# 실제 에이전트를 띄우는 대신, Z-Net_Satut이 읽을 수 있는 
# "가짜 데이터 주입용 인터페이스" 역할을 하는 코드입니다.