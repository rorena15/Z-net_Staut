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
from pysnmp.smi import instrum, builder
from pysnmp.proto import rfc1902
from chaos_simulator import get_simulated_value

class ChaosMibInstrum(instrum.AbstractMibInstrumController):
    def __init__(self):
        # [수정] 여기에 절대 인자가 들어가면 안 됩니다!
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
                    print(f"[*] WALK Request: {oid_str}")
                    if "1.3.6.1.2.1.2.2.1.2" in oid_str:
                        next_oid = rfc1902.ObjectName("1.3.6.1.2.1.2.2.1.2.1")
                        res.append((next_oid, rfc1902.OctetString("Simulated-Eth0")))
                    else:
                        res.append((oid, rfc1902.EndOfMibView()))
                else:
                    print(f"[*] GET  Request: {oid_str} -> {sim_val}")
                    if "1.3.6.1.2.1.1.1.0" in oid_str:
                        res.append((oid, rfc1902.OctetString("Z-Net_Satut Virtual Agent v1.0")))
                    elif "1.3.6.1.2.1.6.9.0" in oid_str:
                        res.append((oid, rfc1902.Integer32(int(sim_val))))
                    elif "1.3.6.1.2.1.2.2.1" in oid_str:
                        res.append((oid, rfc1902.Counter32(int(sim_val))))
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