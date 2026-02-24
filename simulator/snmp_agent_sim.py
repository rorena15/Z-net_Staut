import asyncio
import time
import sys
import os

# 경로 설정
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.smi import instrum, builder
from pysnmp.proto import rfc1902
from chaos_simulator import get_simulated_value

class ChaosMibInstrum(instrum.MibInstrumController):
    def read_vars(self, var_binds, ac_info=(None, None)):
        new_vars = []
        for oid, val in var_binds:
            oid_str = str(oid)
            sim_val = get_simulated_value(oid_str, self.start_time)
            print(f"[*] GET Request: {oid_str} -> {sim_val}")
            
            if "1.3.6.1.2.1.1.1.0" in oid_str:
                new_vars.append((oid, rfc1902.OctetString("Z-Net_Satut Virtual Agent v1.0")))
            elif "1.3.6.1.2.1.2.2.1" in oid_str:
                new_vars.append((oid, rfc1902.Counter32(int(sim_val))))
            else:
                new_vars.append((oid, rfc1902.Integer(int(sim_val))))
        return new_vars

    def read_next_vars(self, var_binds, ac_info=(None, None)):
        new_vars = []
        for oid, val in var_binds:
            oid_str = str(oid)
            print(f"[*] WALK Request: {oid_str}")
            if oid_str == "1.3.6.1.2.1.2.2.1.2":
                next_oid = rfc1902.ObjectName("1.3.6.1.2.1.2.2.1.2.1")
                new_vars.append((next_oid, rfc1902.OctetString("Simulated-Eth0")))
            else:
                new_vars.append((oid, rfc1902.EndOfMibView()))
        return new_vars

async def start_agent():
    # 모든 초기화를 async 루프 안에서 수행
    snmp_engine = engine.SnmpEngine()
    
    config.add_transport(
        snmp_engine,
        udp.DOMAIN_NAME,
        udp.UdpAsyncioTransport().open_server_mode(('127.0.0.1', 1161))
    )
    
    # [교정] add_v2c_user 줄을 삭제했습니다. 
    # add_v1_system이 v1과 v2c(Community-based) 보안을 모두 담당합니다.
    config.add_v1_system(snmp_engine, 'my-area', 'public')
    
    snmp_context = context.SnmpContext(snmp_engine)
    
    mib_builder = builder.MibBuilder()
    chaos_instrum = ChaosMibInstrum(mib_builder)
    chaos_instrum.start_time = time.time()
    
    try:
        snmp_context.unregister_context_name(b'')
    except:
        pass
        
    snmp_context.register_context_name(b'', chaos_instrum)
    cmdrsp.GetCommandResponder(snmp_engine, snmp_context)
    cmdrsp.NextCommandResponder(snmp_engine, snmp_context)
    
    print("[*] Z-Net_Satut Agent LIVE | Port: 1161 (UDP)")
    
    while True:
        await asyncio.sleep(1)

if __name__ == "__main__":
    # Windows 비동기 네트워크 통신을 위한 필수 정책 설정
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    try:
        asyncio.run(start_agent())
    except KeyboardInterrupt:
        print("\nStopped.")