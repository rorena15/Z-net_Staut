import random
import time
import math

def get_simulated_value(oid, start_time):
    elapsed = time.time() - start_time
    
    # [1] TCP Sessions (1.3.6.1.2.1.6.9.0) - 안정화 로직
    if "1.6.9.0" in oid:
        # 세션용 노이즈는 더 작게 설정 (0.2% 내외)
        session_noise = random.gauss(1.0, 0.002)
        base = 180
        
        if elapsed < 30:
            # 정상: 180 내외 유지
            return int(base * session_noise)
        
        elif 30 <= elapsed < 80:
            # 30~80초: 목표치(4200)까지 부드럽게 상승 (S-Curve 모사)
            # 선형 증가가 아닌 가속/감속을 섞어 자연스럽게 연결
            progress = (elapsed - 30) / 50  # 0.0 ~ 1.0
            # Sigmoid와 유사한 부드러운 증가 곡선
            smooth_step = (math.sin((progress * math.pi) - (math.pi / 2)) + 1) / 2
            val = base + (smooth_step * (4200 - base))
            return int(val * session_noise)
            
        else:
            # 80초 이후: 고부하 상태 유지 (미세한 흔들림만 부여)
            return int(4200 * session_noise)

    # [2] In/Out Traffic (Counter) - 가속도 및 연속성 유지
    elif "1.2.2.1.10" in oid or "1.2.2.1.16" in oid:
        traffic_noise = random.gauss(1.0, 0.005)
        start_offset = 104857600 
        
        if elapsed < 40:
            cumulative = start_offset + (1048576 * elapsed)
        elif 40 <= elapsed < 80:
            base_40 = start_offset + (40 * 1048576)
            ramp = math.pow(elapsed - 40, 2) * 500000 
            cumulative = base_40 + ramp
        else:
            # 80초 지점 연속성 확보
            base_80 = start_offset + (40 * 1048576) + (40**2 * 500000)
            attack_time = elapsed - 80
            # 가속도 붙은 누적 (Delta가 계속 커짐)
            current_bps = (100 * 1048576) + (attack_time * 15 * 1048576)
            cumulative = base_80 + (attack_time * current_bps)
            
        return int(cumulative * traffic_noise)

    return int(100 * random.random())