import random
import time
import math

# 상수 설정
B_1MB = 1048576
B_100MB = 104857600

# 시나리오 타임라인 (초 단위)
T_NORMAL = 1200   # 20분까지 정상 상태 유지
T_WARMUP = 1500   # 20분~25분 사이 점진적 증가 (징후)
# 1500초(25분) 이후 본격 공격 시작

def get_simulated_value(oid, start_time):
    elapsed = time.time() - start_time
    
    # [1] TCP Sessions (1.3.6.1.2.1.6.9.0)
    if "1.6.9.0" in oid:
        noise = random.gauss(1.0, 0.002)
        base = 180
        target = 4200
        
        if elapsed < T_NORMAL:
            return int(base * noise)
        elif T_NORMAL <= elapsed < T_WARMUP:
            # 20분부터 25분까지 부드럽게 세션 증가
            progress = (elapsed - T_NORMAL) / (T_WARMUP - T_NORMAL)
            smooth_step = (math.sin((progress * math.pi) - (math.pi / 2)) + 1) / 2
            val = base + (smooth_step * (target - base))
            return int(val * noise)
        else:
            return int(target * noise)

    # [2] In/Out Traffic (Counter)
    elif "1.2.2.1.10" in oid or "1.2.2.1.16" in oid:
        noise = random.gauss(1.0, 0.005)
        start_offset = B_100MB 
        
        # 연속성을 위한 경계점 계산
        val_at_normal = start_offset + (B_1MB * T_NORMAL)
        # Warmup 기간(300초) 동안 가속 증가분 계산
        warmup_duration = T_WARMUP - T_NORMAL
        val_at_warmup = val_at_normal + (math.pow(warmup_duration, 2) * 20000)
        
        if elapsed < T_NORMAL:
            # 1단계: 20분간 평시 트래픽 (초당 1MB 누적)
            cumulative = start_offset + (B_1MB * elapsed)
        elif T_NORMAL <= elapsed < T_WARMUP:
            # 2단계: 20~25분 사이 이상 징후 (서서히 가속)
            t = elapsed - T_NORMAL
            cumulative = val_at_normal + (math.pow(t, 2) * 20000)
        else:
            # 3단계: 25분 이후 본격 공격 (Delta 폭발)
            t = elapsed - T_WARMUP
            # 기본 초당 100MB 증가 + 초당 5MB씩 추가 가속 (장기 실행 고려 가속도 하향)
            current_rate = (100 * B_1MB) + (t * 5 * B_1MB)
            cumulative = val_at_warmup + (t * current_rate)
            
        return int(cumulative * noise)

    return int(100 * random.random())