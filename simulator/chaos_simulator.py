import random
import time
import math

def get_simulated_value(oid, start_time):
    elapsed = time.time() - start_time
    # 노이즈 범위를 줄여 안정성을 높임 (0.5% 내외)
    noise = random.gauss(1.0, 0.005) 
    
    # [1] TCP Sessions (Gauge: 증감 가능하므로 기존 노이즈 유지)
    if "1.6.9.0" in oid:
        base = 180
        if elapsed < 30:
            return int(base * noise)
        elif 30 <= elapsed < 60:
            return int((base + (elapsed - 30) * 40) * noise)
        else:
            return int(4200 * noise)

    # [2] In/Out Traffic (Counter: 무조건 이전보다 커야 함)
    elif "1.2.2.1.10" in oid or "1.2.2.1.16" in oid:
        # 시작 기준점 (약 100MB 지점부터 누적 시작)
        start_offset = 104857600 
        
        if elapsed < 40: # 정상 구간을 40초로 약간 늘림 (4회 스캔 보장)
            # 초당 1MB씩 꾸준히 증가
            bps = 1048576 
            cumulative = start_offset + (bps * elapsed * noise)
        elif 40 <= elapsed < 80:
            # 초당 증가 폭이 가파르게 상승 (공격 준비)
            bps_base = 1048576
            ramp = math.pow(elapsed - 40, 2) * 500000 
            cumulative = start_offset + (40 * bps_base) + ramp
        else:
            # 폭발적 증가 (공격 발생)
            cumulative = start_offset + (elapsed * 100 * 1048576) # 초당 100MB씩 증가
            
        return int(cumulative)

    return int(100 * noise)