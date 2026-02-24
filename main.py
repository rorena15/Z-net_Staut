import asyncio
import os
from datetime import datetime
from snmp_engine import ZNetSatutEngineAsync
from db_manager import init_db, save_to_db
from config import TARGETS, DB_NAME, SCAN_INTERVAL, THRESHOLD

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
    print(f"\n[ Z-Net_Satut Real-Time Monitor ] - {scan_time}")
    print("=" * 115)
    print(f"{'Target IP':<18} | {'Metric':<25} | {'Status':<7} | {'Value':<20} | {'Delta':<10} | {'Alert'}")
    print("-" * 115)
    
    for res in results:
        # 동적 OID 대응 (예: 1.3.6.1.2.1.2.2.1.10.1 -> In_Traffic.1)
        base_oid = ".".join(res['oid'].split('.')[:-1])
        idx = res['oid'].split('.')[-1]
        metric_name = OID_MAP.get(res['oid'], OID_MAP.get(base_oid, res['oid']))
        full_metric = f"{metric_name}.{idx}" if base_oid in OID_MAP else metric_name
        
        val_str = str(res['value'])[:20]
        delta = res.get('delta', 0)
        
        alert_msg = f"{COLOR_OK}[NORMAL]{COLOR_RESET}"
        # Metric 이름에 In_Traffic이나 Out_Traffic이 포함된 경우 임계치 체크
        if isinstance(delta, int):
            for key, limit in THRESHOLD.items():
                if key in full_metric and delta >= limit:
                    alert_msg = f"{COLOR_WARN}[WARNING!]{COLOR_RESET}"
        
        delta_str = str(delta) if delta != '-' else '-'
        print(f"{res['ip']:<18} | {full_metric:<25} | {res['status']:<7} | {val_str:<20} | {delta_str:<10} | {alert_msg}")
        
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