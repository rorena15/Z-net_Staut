import asyncio
from datetime import datetime
from snmp_engine import ZNetSatutEngineAsync
from db_manager import init_db, save_to_db
from config import TARGETS, DB_NAME, SCAN_INTERVAL

async def main():
    engine = ZNetSatutEngineAsync()
    db_conn = init_db(DB_NAME)
    
    print("Z-Net_Satut Continuous Monitoring Started... (Press Ctrl+C to stop)")
    
    try:
        while True:
            scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"[{scan_time}] Scanning targets...")
            
            results = await engine.run_scan(TARGETS)
            save_to_db(db_conn, results)
            
            print(f"[{scan_time}] Saved {len(results)} records to SQLite DB.")
            await asyncio.sleep(SCAN_INTERVAL)
            
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")
    finally:
        db_conn.close()

if __name__ == "__main__":
    asyncio.run(main())