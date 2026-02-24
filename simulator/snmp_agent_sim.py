# simulator/snmp_agent_sim.py
"""
genErr / 요청 미도달 근본 해결:

pysnmp 5.x에서 커스텀 MIB 컨트롤러가 실제로 호출되려면
instrum.MibInstrumController를 상속하되,
내부 디스패처가 찾는 __verifyAccess, getMibInstrum 등
부모 메서드를 그대로 유지해야 함.

핵심: pysnmp 5.x는 GET PDU 수신 시
  context → mibInstrum.readVars() 를 호출하는데,
  이 경로가 동작하려면 MibInstrumController의
  __init__(mibBuilder) 을 반드시 호출해야 함.
"""
import asyncio
import time
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.smi import instrum, builder
from pysnmp.proto import rfc1902
from chaos_simulator import get_simulated_value


class ChaosMibInstrum(instrum.MibInstrumController):
    """
    pysnmp 5.x 호환.

    MibInstrumController를 상속하고 __init__에 MibBuilder를 전달.
    메서드명은 pysnmp 5.x snake_case: read_vars / read_next_vars.
    (AbstractMibInstrumController + camelCase 방식이 genErr를 유발했음)
    """

    def __init__(self, mib_builder):
        # 부모 __init__ 반드시 호출 (내부 _mibBuilder 등 상태 초기화)
        super().__init__(mib_builder)
        self.start_time = time.time()

    # pysnmp 5.x MibInstrumController 실제 호출 메서드 (snake_case)
    def read_vars(self, var_binds, acInfo=None):
        result = []
        for oid, _ in var_binds:
            oid_str = str(oid)
            sim_val = get_simulated_value(oid_str, self.start_time)
            print(f"[*] GET  {oid_str} -> {sim_val}")

            if "1.3.6.1.2.1.1.1.0" in oid_str:
                result.append((oid, rfc1902.OctetString("Z-Net_Satut Virtual Agent v1.0")))
            elif "1.3.6.1.2.1.2.2.1" in oid_str:
                result.append((oid, rfc1902.Counter32(int(sim_val))))
            else:
                result.append((oid, rfc1902.Integer(int(sim_val))))
        return result

    def read_next_vars(self, var_binds, acInfo=None):
        result = []
        for oid, _ in var_binds:
            oid_str = str(oid)
            print(f"[*] WALK {oid_str}")
            if "1.3.6.1.2.1.2.2.1.2" in oid_str:
                next_oid = rfc1902.ObjectName("1.3.6.1.2.1.2.2.1.2.1")
                result.append((next_oid, rfc1902.OctetString("Simulated-Eth0")))
            else:
                result.append((oid, rfc1902.EndOfMibView()))
        return result


async def _probe_api(snmp_context, chaos_instrum):
    """
    pysnmp 버전별 context 등록 API를 자동 감지하여 호출.
    5.x: register_context_name (snake_case)
    4.x: registerContextName  (camelCase)
    """
    registered = False
    for unreg_name in ('unregister_context_name', 'unregisterContextName'):
        fn = getattr(snmp_context, unreg_name, None)
        if fn:
            try:
                fn(b'')
            except Exception:
                pass
            break

    for reg_name in ('register_context_name', 'registerContextName'):
        fn = getattr(snmp_context, reg_name, None)
        if fn:
            fn(b'', chaos_instrum)
            print(f"[*] Context registered via: {reg_name}")
            registered = True
            break

    if not registered:
        raise RuntimeError("SnmpContext에서 register_context_name을 찾을 수 없음")


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
    config.add_vacm_view(snmp_engine, 'my-view', 'included', '1.3.6.1', '')

    # MibBuilder를 생성하고 MibInstrumController에 전달 (필수)
    mib_builder   = builder.MibBuilder()
    chaos_instrum = ChaosMibInstrum(mib_builder)

    snmp_context = context.SnmpContext(snmp_engine)
    await _probe_api(snmp_context, chaos_instrum)

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