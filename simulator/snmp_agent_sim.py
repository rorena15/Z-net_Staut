# simulator/snmp_agent_sim.py
import asyncio
import time
import sys
import os

# chaos_simulator 경로: 실행 위치 무관하게 이 파일 기준으로 상위 폴더를 추가
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.smi import instrum, builder
from pysnmp.proto import rfc1902
from chaos_simulator import get_simulated_value

# ────────────────────────────────────────────────────────────────
# [BUG FIX #1] MibInstrumController → AbstractMibInstrumController
#              read_vars / read_next_vars → readVars / readNextVars
#
# 원인: pysnmp 5.x 내부 디스패처는 camelCase 메서드(readVars)를 호출함.
#       snake_case(read_vars)로 정의하면 핸들러가 실행되지 않아
#       varBinds가 비어 있는 응답이 반환되고, Value 컬럼이 빈칸이 됨.
# ────────────────────────────────────────────────────────────────
class ChaosMibInstrum(instrum.AbstractMibInstrumController):

    def __init__(self):
        self.start_time = time.time()

    # GET 요청 처리 (pysnmp 5.x: camelCase 필수)
    def readVars(self, varBinds, acInfo=(None, None)):
        new_vars = []
        for oid, val in varBinds:
            oid_str = str(oid)
            sim_val = get_simulated_value(oid_str, self.start_time)
            print(f"[*] GET Request: {oid_str} -> {sim_val}")

            if "1.3.6.1.2.1.1.1.0" in oid_str:
                # SysDescr: 문자열 응답
                new_vars.append((oid, rfc1902.OctetString("Z-Net_Satut Virtual Agent v1.0")))
            elif "1.3.6.1.2.1.2.2.1" in oid_str:
                # Traffic 카운터: Counter32
                new_vars.append((oid, rfc1902.Counter32(int(sim_val))))
            else:
                # TCP 세션 등 수치 지표: Integer
                new_vars.append((oid, rfc1902.Integer(int(sim_val))))

        return new_vars

    # WALK(GETNEXT) 요청 처리
    def readNextVars(self, varBinds, acInfo=(None, None)):
        new_vars = []
        for oid, val in varBinds:
            oid_str = str(oid)
            print(f"[*] WALK Request: {oid_str}")

            if oid_str == "1.3.6.1.2.1.2.2.1.2":
                next_oid = rfc1902.ObjectName("1.3.6.1.2.1.2.2.1.2.1")
                new_vars.append((next_oid, rfc1902.OctetString("Simulated-Eth0")))
            else:
                new_vars.append((oid, rfc1902.EndOfMibView()))

        return new_vars

    # AbstractMibInstrumController 요구 stub
    def writeVars(self, varBinds, acInfo=(None, None)):
        return varBinds

    def readVarsType(self, varBinds, acInfo=(None, None)):
        return varBinds


async def start_agent():
    snmp_engine = engine.SnmpEngine()

    config.add_transport(
        snmp_engine,
        udp.DOMAIN_NAME,
        udp.UdpAsyncioTransport().open_server_mode(('127.0.0.1', 1161))
    )

    config.add_v1_system(snmp_engine, 'my-area', 'public')
    config.add_vacm_group(snmp_engine, 'my-group', 2, 'my-area')
    config.add_vacm_access(
        snmp_engine, 'my-group', '', 2, 'noAuthNoPriv', 'exact', 'my-view', '', ''
    )
    # (engine, viewName, viewType, subTree, subTreeMask)
    config.add_vacm_view(snmp_engine, 'my-view', 'included', '1.3.6.1', '')

    snmp_context = context.SnmpContext(snmp_engine)

    # [BUG FIX #1 연속] AbstractMibInstrumController는 MibBuilder 인자 불필요
    chaos_instrum = ChaosMibInstrum()

    # [BUG FIX] pysnmp 5.x: camelCase → snake_case API
    try:
        snmp_context.unregister_context_name(b'')
    except Exception:
        pass

    snmp_context.register_context_name(b'', chaos_instrum)
    cmdrsp.GetCommandResponder(snmp_engine, snmp_context)
    cmdrsp.NextCommandResponder(snmp_engine, snmp_context)

    print("[*] Z-Net_Satut Agent LIVE | Port: 1161 (UDP)")
    while True:
        await asyncio.sleep(1)


if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(start_agent())
    except KeyboardInterrupt:
        print("\nStopped.")