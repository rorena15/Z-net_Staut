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
    """
    pysnmp 5.x 호환 커스텀 MIB 컨트롤러.

    genErr 방어 포인트:
      1. super().__init__() 호출 → 부모 클래스 내부 상태 초기화 누락 방지
      2. varBinds 언패킹을 varBind[0]/varBind[1]로 안전하게 처리
         (pysnmp 버전에 따라 VarBind 객체 또는 튜플로 전달될 수 있음)
      3. readVars 전체를 try/except로 감싸 내부 예외가 genErr로
         전파되지 않도록 격리
    """

    def __init__(self):
        # [FIX] 부모 클래스 초기화 누락 → genErr 원인 중 하나
        super().__init__()
        self.start_time = time.time()

    def _make_response(self, varBinds, is_next=False):
        """GET / GETNEXT 공통 응답 생성 로직."""
        new_vars = []
        try:
            for varBind in varBinds:
                # [FIX] 튜플/VarBind 객체 모두 대응
                oid = varBind[0]
                oid_str = str(oid)
                sim_val = get_simulated_value(oid_str, self.start_time)

                if is_next:
                    print(f"[*] WALK  Request: {oid_str}")
                    if oid_str == "1.3.6.1.2.1.2.2.1.2":
                        next_oid = rfc1902.ObjectName("1.3.6.1.2.1.2.2.1.2.1")
                        new_vars.append((next_oid, rfc1902.OctetString("Simulated-Eth0")))
                    else:
                        new_vars.append((oid, rfc1902.EndOfMibView()))
                else:
                    print(f"[*] GET   Request: {oid_str} -> {sim_val}")
                    if "1.3.6.1.2.1.1.1.0" in oid_str:
                        new_vars.append((oid, rfc1902.OctetString("Z-Net_Satut Virtual Agent v1.0")))
                    elif "1.3.6.1.2.1.2.2.1" in oid_str:
                        new_vars.append((oid, rfc1902.Counter32(int(sim_val))))
                    else:
                        new_vars.append((oid, rfc1902.Integer(int(sim_val))))

        except Exception as e:
            # [FIX] 내부 예외를 출력만 하고 genErr로 전파되지 않게 격리
            print(f"[!] MIB handler error: {e}")

        return new_vars

    def readVars(self, varBinds, acInfo=(None, None)):
        return self._make_response(varBinds, is_next=False)

    def readNextVars(self, varBinds, acInfo=(None, None)):
        return self._make_response(varBinds, is_next=True)

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