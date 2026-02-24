import random
import time
import math

def get_simulated_value(oid, start_time):
    elapsed = time.time() - start_time
    
    # [1] 기본 노이즈 및 파동 (Basics)
    # 0.95 ~ 1.05 사이의 가우시안 노이즈 (더 실무적인 흔들림)
    noise = random.gauss(1.0, 0.02)
    # 10초 주기의 완만한 트래픽 파동
    wave = math.sin(elapsed * 0.6) * 0.05
    
    # [2] 랜덤 마이크로 버스트 (정상 상황에서도 가끔 발생하는 일시적 튀튀)
    burst = 0
    if random.random() > 0.92: # 약 8% 확률로 발생
        burst = random.uniform(1.2, 1.5)

    # TCP Sessions (1.3.6.1.2.1.6.9.0)
    if "1.6.9.0" in oid:
        base = 180
        if elapsed < 30:
            val = base * (noise + wave)
            if burst > 0: val *= burst # 정상 범위 내 일시적 상승
            return int(val)
        elif 30 <= elapsed < 60:
            ramp = (elapsed - 30) * 35
            return int((base + ramp) * noise)
        else:
            return int(4200 * noise)

    # Inbound Traffic (1.3.6.1.2.1.2.2.1.10)
    elif "1.2.2.1.10" in oid:
        base_traffic = 8388608 # 약 8MB
        if elapsed < 30:
            val = base_traffic * (noise + wave)
            if burst > 0: val *= (burst * 1.2)
            return int(val)
        elif 30 <= elapsed < 70:
            # 서서히 가속도가 붙는 상승 (Exponential-like)
            ramp = math.pow(elapsed - 30, 1.8) * 1000000
            return int((base_traffic + ramp) * noise)
        else:
            return int(524288000 * noise) # 500MB+ 폭증

    return int(100 * noise)