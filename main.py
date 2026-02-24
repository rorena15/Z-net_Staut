import asyncio
import os
from datetime import datetime
from snmp_engine import ZNetSatutEngineAsync
from db_manager import init_db, save_to_db
from config import TARGETS, DB_NAME, SCAN_INTERVAL

OID_MAP = {
    "1.3.6.1.2.1.1.1.0": "SysDescr",
    "1.3.6.1.2.1.1.5.0": "SysName",
    "1.3.6.1.2.1.6.9.0": "TCP Sessions",
    "1.3.6.1.2.1.2.2.1.10.1": "In_Traffic",
    "1.3.6.1.2.1.2.2.1.16.1": "Out_Traffic"
}

def display_realtime_status(scan_time, results):
    os.system('cls' if os.name == 'nt' else 'clear')
    
    print(f"\n[ Z-Net_Satut Real-Time Monitor ] - {scan_time}")
    print("=" * 90)
    print(f"{'Target IP':<18} | {'Metric':<15} | {'Status':<7} | {'Value':<20} | {'Delta (+)'}")
    print("-" * 90)
    
    for res in results:
        metric = OID_MAP.get(res['oid'], res['oid'])
        val_str = str(res['value'])[:20]
        delta_str = str(res.get('delta', '-'))
        
        print(f"{res['ip']:<18} | {metric:<15} | {res['status']:<7} | {val_str:<20} | {delta_str}")
        
    print("=" * 90)
    print("Press Ctrl+C to stop monitoring...\n")

async def main():
    engine = ZNetSatutEngineAsync()
    db_conn = init_db(DB_NAME)
    previous_data = {}
    
    try:
        while True:
            scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            results = await engine.run_scan(TARGETS)
            
            for res in results:
                key = f"{res['ip']}_{res['oid']}"
                current_val_str = res['value']
                
                try:
                    current_val = int(current_val_str)
                    if key in previous_data:
                        res['delta'] = current_val - previous_data[key]
                    else:
                        res['delta'] = 0
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