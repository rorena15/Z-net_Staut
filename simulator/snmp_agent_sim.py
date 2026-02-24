# simulator/snmp_agent_sim.py
import asyncio
import time
import sys
import os
import warnings
import traceback

warnings.filterwarnings("ignore", category=DeprecationWarning)
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.smi import instrum
from pysnmp.proto import rfc1902, rfc1905  # [수정] rfc1905 추가 임포트
from chaos_simulator import get_simulated_value

class ChaosMibInstrum(instrum.AbstractMibInstrumController):
    def __init__(self):
        super().__init__()
        self.start_time = time.time()

    def _process_binds(self, varBinds, is_next=False):
        res = []
        try:
            for oid, val in varBinds:
                oid_str = str(oid)
                sim_val = get_simulated_value(oid_str, self.start_time)
                if sim_val is None or sim_val == "": sim_val = 0
                
                if is_next:
                    # [WALK 로직 핵심 수정] 무한 루프 방지 및 정확한 응답
                    print(f"[*] WALK Request: {oid_str}")
                    
                    # 1. 인터페이스 목록 시작점 요청 시 (Base OID)
                    if oid_str == "1.3.6.1.2.1.2.2.1.2":
                        next_oid = rfc1902.ObjectName("1.3.6.1.2.1.2.2.1.2.1")
                        res.append((next_oid, rfc1902.OctetString("Simulated-Eth0")))
                    
                    # 2. 이미 값이 있는 인덱스(.1 등)에 대해 다음 값을 요청하면 종료 신호 전송
                    else:
                        # [수정] rfc1902가 아닌 rfc1905.EndOfMibView() 사용
                        res.append((oid, rfc1905.EndOfMibView()))
                else:
                    # GET 요청 처리는 기존과 동일
                    print(f"[*] GET  Request: {oid_str} -> {sim_val}")
                    if "1.3.6.1.2.1.1.1.0" in oid_str:
                        res.append((oid, rfc1902.OctetString("Z-Net_Satut Virtual Agent v1.0")))
                    elif "1.3.6.1.2.1.6.9.0" in oid_str:
                        res.append((oid, rfc1902.Integer32(int(sim_val))))
                    elif "1.3.6.1.2.1.2.2.1" in oid_str:
                        safe_val = int(sim_val) % 4294967296
                        res.append((oid, rfc1902.Counter32(safe_val)))
                    else:
                        res.append((oid, rfc1902.Integer32(int(sim_val))))
            return tuple(res)
        except Exception as e:
            print(f"[!] 내부 에러: {e}")
            traceback.print_exc()
            return varBinds

    def read_variables(self, *varBinds, **context):
        return self._process_binds(varBinds, False)

    def read_next_variables(self, *varBinds, **context):
        return self._process_binds(varBinds, True)

async def start_agent():
    snmp_engine = engine.SnmpEngine()
    
    config.add_transport(
        snmp_engine,
        udp.DOMAIN_NAME,
        udp.UdpAsyncioTransport().open_server_mode(('127.0.0.1', 1161))
    )

    config.add_v1_system(snmp_engine, 'my-area', 'public')
    config.add_vacm_user(snmp_engine, 2, 'my-area', 'noAuthNoPriv', (1, 3, 6))

    chaos_instrum = ChaosMibInstrum()
    snmp_context = context.SnmpContext(snmp_engine)
    
    try:
        getattr(snmp_context, 'unregisterContextName', getattr(snmp_context, 'unregister_context_name'))(b'')
    except Exception:
        pass
    getattr(snmp_context, 'registerContextName', getattr(snmp_context, 'register_context_name'))(b'', chaos_instrum)

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