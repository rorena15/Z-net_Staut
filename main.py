# main.py
import asyncio
import os
import sys
import re as _re
from datetime import datetime
from snmp_engine import ZNetSatutEngineAsync
from db_manager import init_db, save_to_db
from config import TARGETS, DB_NAME, SCAN_INTERVAL, THRESHOLD
from library import get_oid_info

COLOR_RESET = "\033[0m"
COLOR_WARN  = "\033[91m"
COLOR_OK    = "\033[92m"
COLOR_DIM   = "\033[90m"
COLOR_BOLD  = "\033[1m"

_SENTINEL = object()

# 컬럼 너비 (화면 출력 기준, ANSI 코드 제외)
_W_IP    = 18
_W_NAME  = 25
_W_CAT   = 12
_W_VAL   = 18
_W_DELTA =  8
_W_STS   = 10
_LINE    = 135


def _ansi_ljust(s: str, width: int) -> str:
    """
    ANSI 이스케이프 코드를 제외한 실제 출력 문자 수 기준으로 ljust.
    일반 f-string ljust는 ANSI 코드 바이트까지 길이에 포함하여
    Status 컬럼이 ONLINE/OFFLINE 이후 들쭉날쭉하게 정렬되는 문제를 해결.
    """
    visible = len(_re.sub(r'\033\[[0-9;]*m', '', s))
    return s + ' ' * max(0, width - visible)


def _fmt_row(ip, name, cat, val, delta, status, intel):
    """컬럼 고정폭 행. ANSI 포함 컬럼(status)은 _ansi_ljust 사용."""
    return (
        f"{ip:<{_W_IP}} | "
        f"{name:<{_W_NAME}} | "
        f"{cat:<{_W_CAT}} | "
        f"{val:<{_W_VAL}} | "
        f"{delta:<{_W_DELTA}} | "
        f"{_ansi_ljust(status, _W_STS)} | "
        f"{intel}"
    )


def display_realtime_status(scan_time, results):
    os.system('cls' if os.name == 'nt' else 'clear')

    SEP = "=" * _LINE
    DIV = "-" * _LINE

    print(f"\n{COLOR_BOLD}[ Z-Net_Satut SecOps Monitor ]{COLOR_RESET} - {scan_time}")
    print(SEP)
    print(_fmt_row(
        "Target IP", "Metric Name", "Category",
        "Value", "Delta", "Status", "Security Intelligence"
    ))
    print(DIV)

    for res in results:
        info  = get_oid_info(res['oid'])
        delta = res.get('delta')

        # Value (18자 truncate)
        val_str = (str(res['value']) if res['value'] is not None else '-')[:_W_VAL]

        # Delta
        delta_str = '-' if (delta is None or delta == '-') else str(delta)

        # Status
        if res.get('status') == 'Success':
            status_str = f"{COLOR_OK}ONLINE{COLOR_RESET}"
        else:
            status_str = f"{COLOR_WARN}OFFLINE{COLOR_RESET}"

        # Security Intelligence
        intel_tag = f"{COLOR_OK}[NORMAL]{COLOR_RESET}"
        intel_msg = ""

        if isinstance(delta, int):
            if info['name'].startswith("SysUpTime") and delta < 0:
                intel_tag = f"{COLOR_WARN}[ALERT]{COLOR_RESET}"
                intel_msg = info.get('alert_context', "장비 상태 변화 감지")
            else:
                for key, limit in THRESHOLD.items():
                    if key in info['name'] and delta >= limit:
                        intel_tag = f"{COLOR_WARN}[CRITICAL]{COLOR_RESET}"
                        intel_msg = info.get('alert_context', "이상 징후 발생")
        else:
            # delta가 None(첫 수집) 또는 '-'(문자열) 모두 N/A
            intel_tag = f"{COLOR_DIM}[N/A]{COLOR_RESET}"

        intel_col = f"{intel_tag} {intel_msg}".strip()

        print(_fmt_row(
            res['ip'], info['name'], info['category'],
            val_str, delta_str, status_str, intel_col
        ))

    print(SEP)
    print("Press Ctrl+C to stop monitoring...\n")


async def main():
    engine    = ZNetSatutEngineAsync()
    db_conn   = init_db(DB_NAME)
    previous_data: dict = {}

    print("[*] Initializing Z-Net_Satut Dynamic Engine...")
    dynamic_targets = list(TARGETS)

    # 인터페이스 자동 탐색 (Walk) - IP당 1회만
    seen_ips = set()
    for target in TARGETS:
        ip, port, oid, comm, proto = target
        if ip in seen_ips or "1.1.1.0" not in oid:
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
                    res['delta'] = None          # 첫 회: 기준값 없음
                elif current_val >= prev:
                    res['delta'] = current_val - prev
                else:
                    # Counter32 wrap-around
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