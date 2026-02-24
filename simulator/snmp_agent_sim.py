# simulator/snmp_agent_sim.py
import asyncio
import time
import sys
import os

# 상위 경로의 chaos_simulator를 찾기 위한 설정
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
            
            # SysDescr(기본정보) 요청 시 문자열 응답
            if "1.3.6.1.2.1.1.1.0" in oid_str:
                new_vars.append((oid, rfc1902.OctetString("Z-Net_Satut Virtual Agent v1.0")))
            # Traffic 데이터 (Counter32)
            elif "1.3.6.1.2.1.2.2.1" in oid_str:
                new_vars.append((oid, rfc1902.Counter32(int(sim_val))))
            # 기타 (Integer)
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
    snmp_engine = engine.SnmpEngine()
    
    # 전송 계층 설정 (중복 제거)
    config.add_transport(
        snmp_engine,
        udp.DOMAIN_NAME,
        udp.UdpAsyncioTransport().open_server_mode(('127.0.0.1', 1161))
    )
    
    # 1. 보안 설정: Community 'public' -> securityName 'my-area'
    config.add_v1_system(snmp_engine, 'my-area', 'public')
    
    # 2. VACM Group 등록 (engine, groupName, securityModel[2=v2c], securityName)
    config.add_vacm_group(snmp_engine, 'my-group', 2, 'my-area')
    
    # 3. VACM Access 설정 (engine, group, prefix, model, level, match, readView, writeView, notifyView)
    config.add_vacm_access(
        snmp_engine, 'my-group', '', 2, 'noAuthNoPriv', 'exact', 'my-view', '', ''
    )
    
    # 4. VACM View 설정 교정: 5번째 인자 subTreeMask('')를 추가하여 TypeError 해결
    config.add_vacm_view(snmp_engine, 'my-view', 'included', '1.3.6.1', '')
    
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
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(start_agent())
    except KeyboardInterrupt:
        print("\nStopped.")