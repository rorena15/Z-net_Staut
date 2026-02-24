# main.py
import asyncio
import os
import sys
from datetime import datetime
from snmp_engine import ZNetSatutEngineAsync
from db_manager import init_db, save_to_db
from config import TARGETS, DB_NAME, SCAN_INTERVAL, THRESHOLD
from library import get_oid_info

# ────────────────────────────────────────────────────────────────
# [BUG FIX #3] OID_MAP dead code 제거 (library.py의 get_oid_info와 중복)
# ────────────────────────────────────────────────────────────────

COLOR_RESET = "\033[0m"
COLOR_WARN  = "\033[91m"
COLOR_OK    = "\033[92m"
COLOR_DIM   = "\033[90m"
COLOR_BOLD  = "\033[1m"

_SENTINEL = object()  # 첫 회 감지용 sentinel

# 컬럼 너비 (| 구분자 포함 전체 135자 맞춤)
_W = {
    'ip':      18,
    'name':    25,
    'cat':     12,
    'val':     18,
    'delta':    8,
    'status':  10,
}
_SEP   = " | "
_WIDTH = sum(_W.values()) + len(_SEP) * (len(_W)) + 25  # intel 컬럼 포함


def _row(ip, name, cat, val, delta, status_str, intel):
    """컬럼 너비를 맞춘 한 행 반환 (ANSI 코드 포함)"""
    # ANSI 코드는 출력 너비에 영향 없으므로 ljust는 raw 문자열 기준으로 계산
    return (
        f"{ip:<{_W['ip']}}{_SEP}"
        f"{name:<{_W['name']}}{_SEP}"
        f"{cat:<{_W['cat']}}{_SEP}"
        f"{val:<{_W['val']}}{_SEP}"
        f"{delta:<{_W['delta']}}{_SEP}"
        f"{status_str:<{_W['status']}}      {_SEP}"
        f"{intel}"
    )


def display_realtime_status(scan_time, results):
    os.system('cls' if os.name == 'nt' else 'clear')

    divider = "=" * 135
    thin    = "-" * 135

    print(f"\n{COLOR_BOLD}[ Z-Net_Satut SecOps Monitor ]{COLOR_RESET} - {scan_time}")
    print(divider)
    print(_row("Target IP", "Metric Name", "Category",
               "Value", "Delta", "Status", "Security Intelligence"))
    print(thin)

    for res in results:
        info    = get_oid_info(res['oid'])
        val_raw = res['value']
        delta   = res.get('delta')

        # ── Value 문자열 (18자 truncate) ──
        val_str = (str(val_raw) if val_raw is not None else '-')[:18]

        # ── Status 컬럼 ──
        if res.get('status') == 'Success':
            status_str = f"{COLOR_OK}ONLINE{COLOR_RESET}"
        else:
            status_str = f"{COLOR_WARN}OFFLINE{COLOR_RESET}"

        # ── Delta 컬럼 ──
        if delta is None:
            delta_str = f"{COLOR_DIM}-{COLOR_RESET}"
        elif delta == '-':
            delta_str = '-'
        else:
            delta_str = str(delta)

        # ── Security Intelligence ──
        intel_str = f"{COLOR_OK}[NORMAL]{COLOR_RESET}"
        intel_msg = ""

        if isinstance(delta, int):
            if info['name'].startswith("SysUpTime") and delta < 0:
                intel_str = f"{COLOR_WARN}[ALERT]{COLOR_RESET}"
                intel_msg = info.get('alert_context', "장비 상태 변화 감지")

            for key, limit in THRESHOLD.items():
                if key in info['name'] and delta >= limit:
                    intel_str = f"{COLOR_WARN}[CRITICAL]{COLOR_RESET}"
                    intel_msg = info.get('alert_context', "이상 징후 발생")
        elif delta in (None, '-'):
            intel_str = f"{COLOR_DIM}[N/A]{COLOR_RESET}"

        intel_col = f"{intel_str} {intel_msg}".strip()

        print(_row(
            res['ip'], info['name'], info['category'],
            val_str, delta_str, status_str, intel_col
        ))

    print(divider)
    print("Press Ctrl+C to stop monitoring...\n")


async def main():
    engine    = ZNetSatutEngineAsync()
    db_conn   = init_db(DB_NAME)

    # ── [BUG FIX #3] sentinel으로 '아직 수집 안 됨'과 '값=0'을 구분 ──
    # previous_data[key] = _SENTINEL  → 첫 회 → delta=None
    # previous_data[key] = 0          → 이전값이 실제 0 → delta 계산
    previous_data: dict = {}

    print("[*] Initializing Z-Net_Satut Dynamic Engine...")
    dynamic_targets = list(TARGETS)   # config 기본 타겟 복사

    # 인터페이스 자동 탐색 (Walk)
    seen_ips = set()
    for target in TARGETS:
        ip, port, oid, comm, proto = target
        if ip in seen_ips:
            continue
        if "1.1.1.0" not in oid:
            continue

        seen_ips.add(ip)
        print(f"[*] Scanning interfaces for {ip}...")
        try:
            ifaces = await engine.walk_interfaces(ip, port, comm, proto)
            for iface in ifaces:
                idx = iface['index']
                dynamic_targets.append((ip, port, f"1.3.6.1.2.1.2.2.1.10.{idx}", comm, proto))
                dynamic_targets.append((ip, port, f"1.3.6.1.2.1.2.2.1.16.{idx}", comm, proto))
            print(f"[*] Found {len(ifaces)} interface(s) on {ip}")
        except Exception as e:
            print(f"[!] Walk failed for {ip}: {e}")

    # 실시간 모니터링 루프
    try:
        while True:
            scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            results   = await engine.run_scan(dynamic_targets)

            for res in results:
                key = f"{res['ip']}_{res['oid']}"

                if res['status'] != 'Success':
                    res['delta'] = '-'
                    continue

                try:
                    current_val = int(res['value'])
                except (ValueError, TypeError):
                    res['delta'] = '-'
                    continue

                prev = previous_data.get(key, _SENTINEL)

                if prev is _SENTINEL:
                    # ── [BUG FIX #3] 첫 회: delta 없음을 None으로 명시 ──
                    res['delta'] = None
                else:
                    # Counter32 wrap-around 처리
                    if current_val >= prev:
                        res['delta'] = current_val - prev
                    else:
                        res['delta'] = (4_294_967_295 - prev) + current_val + 1

                previous_data[key] = current_val

            save_to_db(db_conn, results)
            display_realtime_status(scan_time, results)
            await asyncio.sleep(SCAN_INTERVAL)

    except asyncio.CancelledError:
        pass
    finally:
        db_conn.close()
        print("\nMonitoring stopped. Database connection closed safely.")


if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass