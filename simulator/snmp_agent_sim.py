# simulator/snmp_agent_sim.py
import asyncio
import time
import sys
import os
import warnings

# Python 3.13 및 asyncio 관련 경고를 숨깁니다.
warnings.filterwarnings("ignore", category=DeprecationWarning)

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.smi import instrum
from pysnmp.proto import rfc1902
from chaos_simulator import get_simulated_value

class ChaosMibInstrum(instrum.AbstractMibInstrumController):
    # [교정 1] 인자 없이 초기화해야 TypeError가 발생하지 않습니다.
    def __init__(self):
        super().__init__()
        self.start_time = time.time()

    def _process_binds(self, var_binds, is_next=False):
        result = []
        for oid, _ in var_binds:
            oid_str = str(oid)
            sim_val = get_simulated_value(oid_str, self.start_time)
            
            if is_next:
                print(f"[*] WALK Request: {oid_str}")
                if "1.3.6.1.2.1.2.2.1.2" in oid_str:
                    next_oid = rfc1902.ObjectName("1.3.6.1.2.1.2.2.1.2.1")
                    result.append((next_oid, rfc1902.OctetString("Simulated-Eth0")))
                else:
                    result.append((oid, rfc1902.EndOfMibView()))
            else:
                print(f"[*] GET  Request: {oid_str} -> {sim_val}")
                if "1.3.6.1.2.1.1.1.0" in oid_str:
                    result.append((oid, rfc1902.OctetString("Z-Net_Satut Virtual Agent v1.0")))
                elif "1.3.6.1.2.1.6.9.0" in oid_str:
                    result.append((oid, rfc1902.Integer(int(sim_val))))
                elif "1.3.6.1.2.1.2.2.1" in oid_str:
                    result.append((oid, rfc1902.Counter32(int(sim_val))))
                else:
                    result.append((oid, rfc1902.Integer(int(sim_val))))
        return result

    # pysnmp 버전별 핸들러 이름 호환성 확보
    def readVars(self, v, a=None): return self._process_binds(v, False)
    def read_vars(self, v, a=None): return self._process_binds(v, False)
    def readNextVars(self, v, a=None): return self._process_binds(v, True)
    def read_next_vars(self, v, a=None): return self._process_binds(v, True)

async def start_agent():
    snmp_engine = engine.SnmpEngine()
    
    config.add_transport(
        snmp_engine,
        udp.DOMAIN_NAME,
        udp.UdpAsyncioTransport().open_server_mode(('127.0.0.1', 1161))
    )

    config.add_v1_system(snmp_engine, 'my-area', 'public')
    config.add_vacm_group(snmp_engine, 'my-group', 2, 'my-area')
    config.add_vacm_access(snmp_engine, 'my-group', '', 2, 'noAuthNoPriv', 'exact', 'my-view', '', '')
    
    # [교정 2] 정확한 인자 순서: (engine, viewName, viewType, subTree, subTreeMask)
    config.add_vacm_view(snmp_engine, 'my-view', 'included', '1.3.6.1', '')

    # [교정 1 연장] 불필요한 mib_builder 제거
    chaos_instrum = ChaosMibInstrum()
    snmp_context = context.SnmpContext(snmp_engine)
    
    # 중복 컨텍스트 에러 방지용 초기화
    for unreg_name in ('unregister_context_name', 'unregisterContextName'):
        unreg_fn = getattr(snmp_context, unreg_name, None)
        if unreg_fn:
            try: unreg_fn(b'')
            except: pass
            break

    for reg_name in ('register_context_name', 'registerContextName'):
        reg_fn = getattr(snmp_context, reg_name, None)
        if reg_fn:
            reg_fn(b'', chaos_instrum)
            break

    cmdrsp.GetCommandResponder(snmp_engine, snmp_context)
    cmdrsp.NextCommandResponder(snmp_engine, snmp_context)

    print("[*] Z-Net_Satut Agent LIVE | Port: 1161 (UDP)")
    while True:
        await asyncio.sleep(1)

if __name__ == "__main__":
    try:
        asyncio.run(start_agent())
    except KeyboardInterrupt:
        print("\nStopped.")