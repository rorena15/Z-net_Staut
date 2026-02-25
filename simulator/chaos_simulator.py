import random
import time
import math

B_1MB = 1048576
B_100MB = 104857600
T_NORMAL = 1200
T_WARMUP = 1500

def get_simulated_value(oid, start_time):
    elapsed = time.time() - start_time
    
    if "1.6.9.0" in oid:
        noise = random.gauss(1.0, 0.002)
        base = 180
        target = 4200
        
        if elapsed < T_NORMAL:
            return int(base * noise)
        elif T_NORMAL <= elapsed < T_WARMUP:
            progress = (elapsed - T_NORMAL) / (T_WARMUP - T_NORMAL)
            smooth_step = (math.sin((progress * math.pi) - (math.pi / 2)) + 1) / 2
            return int((base + (smooth_step * (target - base))) * noise)
        else:
            return int(target * noise)

    elif "1.2.2.1.10" in oid or "1.2.2.1.16" in oid:
        val_at_normal = B_100MB + (B_1MB * T_NORMAL)
        warmup_duration = T_WARMUP - T_NORMAL
        val_at_warmup = val_at_normal + (math.pow(warmup_duration, 2) * 20000)
        
        if elapsed < T_NORMAL:
            cumulative = B_100MB + (B_1MB * elapsed)
        elif T_NORMAL <= elapsed < T_WARMUP:
            t = elapsed - T_NORMAL
            cumulative = val_at_normal + (math.pow(t, 2) * 20000)
        else:
            t = elapsed - T_WARMUP
            current_rate = (100 * B_1MB) + (t * 5 * B_1MB)
            cumulative = val_at_warmup + (t * current_rate)
            
        jitter = random.randint(-50000, 50000)
        return int(cumulative) + jitter

    return int(100 * random.random())