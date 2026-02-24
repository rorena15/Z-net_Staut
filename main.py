import asyncio
import os
from datetime import datetime
from snmp_engine import ZNetSatutEngineAsync
from db_manager import init_db, save_to_db
from config import TARGETS, DB_NAME, SCAN_INTERVAL, THRESHOLD
from library import get_oid_info

# OID를 사람이 읽기 쉬운 이름으로 매핑 (인덱스 제외한 기본형)
OID_MAP = {
    "1.3.6.1.2.1.1.1.0": "SysDescr",
    "1.3.6.1.2.1.1.5.0": "SysName",
    "1.3.6.1.2.1.6.9.0": "TCP Sessions",
    "1.3.6.1.2.1.2.2.1.10": "In_Traffic",  # .index가 붙으므로 마지막 0 제거
    "1.3.6.1.2.1.2.2.1.16": "Out_Traffic"
}

COLOR_RESET = "\033[0m"
COLOR_WARN = "\033[91m"
COLOR_OK = "\033[92m"

def display_realtime_status(scan_time, results):
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"\n[ Z-Net_Satut SecOps Monitor ] - {scan_time}")
    print("=" * 115)
    print(f"{'Target IP':<18} | {'Metric Name':<28} | {'Category':<12} | {'Value':<18} | {'Delta':<8} | {'Security Intelligence'}")
    print("-" * 115)
    
    for res in results:
        info = get_oid_info(res['oid'])
        val_str = str(res['value'])[:18]
        delta = res.get('delta', 0)
        
        status_msg = f"{COLOR_OK}[NORMAL]{COLOR_RESET}"
        intelligence_msg = "" # 평소에는 조용히
        
        # 지능형 문맥 분석 (Strategy 2 핵심)
        if isinstance(delta, int):
            # 1. 재부팅 감지 (UpTime이 이전보다 작아졌을 때)
            if info['name'].startswith("SysUpTime") and delta < 0:
                status_msg = f"{COLOR_WARN}[ALERT]{COLOR_RESET}"
                intelligence_msg = info.get('alert_context', "장비 상태 변화 감지")
            
            # 2. 임계치 기반 분석
            for key, limit in THRESHOLD.items():
                if key in info['name'] and delta >= limit:
                    status_msg = f"{COLOR_WARN}[CRITICAL]{COLOR_RESET}"
                    intelligence_msg = info.get('alert_context', "이상 징후 발생")
        
        print(f"{res['ip']:<18} | {info['name']:<28} | {info['category']:<12} | {val_str:<18} | {delta:<8} | {status_msg} {intelligence_msg}")
    
    print("=" * 115)
    print("Press Ctrl+C to stop monitoring...\n")

async def main():
    engine = ZNetSatutEngineAsync()
    db_conn = init_db(DB_NAME)
    previous_data = {}
    
    # 1. 동적 타겟 생성 (인터페이스 자동 스캔)
    print("[*] Initializing Z-Net_Satut Dynamic Engine...")
    dynamic_targets = []
    
    for target in TARGETS:
        ip, port, oid, comm, proto = target
        # 고정 타겟 추가
        dynamic_targets.append(target)
        
        # 인터페이스 자동 탐색 (Walk) 실행
        # 만약 snmp_engine에 walk_interfaces를 만들었다면 여기서 호출
        try:
            if "1.1.1.0" in oid: # 장비 기본 정보를 확인하는 타겟일 때만 Walk 시도
                print(f"[*] Scanning interfaces for {ip}...")
                ifaces = await engine.walk_interfaces(ip, port, comm, proto)
                for iface in ifaces:
                    # In(10), Out(16) 트래픽 OID를 발견된 모든 인덱스에 대해 추가
                    dynamic_targets.append((ip, port, f"1.3.6.1.2.1.2.2.1.10.{iface['index']}", comm, proto))
                    dynamic_targets.append((ip, port, f"1.3.6.1.2.1.2.2.1.16.{iface['index']}", comm, proto))
        except Exception as e:
            print(f"[!] Walk failed for {ip}: {e}")

    # 2. 실시간 모니터링 루프
    try:
        while True:
            scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            results = await engine.run_scan(dynamic_targets)
            
            for res in results:
                key = f"{res['ip']}_{res['oid']}"
                try:
                    current_val = int(res['value'])
                    res['delta'] = current_val - previous_data.get(key, current_val)
                    previous_data[key] = current_val
                except (ValueError, TypeError):
                    res['delta'] = '-'
            
            save_to_db(db_conn, results)
            display_realtime_status(scan_time, results)
            await asyncio.sleep(SCAN_INTERVAL)
            
    except asyncio.CancelledError:
        pass
    finally:
        db_conn.close()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user. Database connection closed safely.")