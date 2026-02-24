# simulator/snmp_agent_sim.py
import asyncio
import time
import sys
import os

# 상위 디렉토리의 chaos_simulator를 찾기 위한 경로 설정
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.smi import instrum, builder
from pysnmp.proto import rfc1902
from chaos_simulator import get_simulated_value

# 1. SNMP 엔진 설정
snmp_engine = engine.SnmpEngine()

# 2. 전송 계층 설정 (UDP 1161)
config.add_transport(
    snmp_engine,
    udp.DOMAIN_NAME,
    udp.UdpAsyncioTransport().open_server_mode(('127.0.0.1', 1161))
)

# 3. SNMP 커뮤니티 및 보안 설정
config.add_v1_system(snmp_engine, 'my-area', 'public')
snmp_context = context.SnmpContext(snmp_engine)
start_time = time.time()

# 4. 요청 처리 핸들러 (Get 및 Next/Walk 모두 대응)
class ChaosMibInstrum(instrum.MibInstrumController):
    def read_vars(self, var_binds, ac_info=(None, None)):
        new_vars = []
        for oid, val in var_binds:
            oid_str = str(oid)
            sim_val = get_simulated_value(oid_str, start_time)
            # [로그 추가] 요청이 오면 무조건 찍힙니다.
            print(f"[*] GET Request: {oid_str} -> Response: {sim_val}")
            
            from pysnmp.proto import rfc1902
            if "1.3.6.1.2.1.2.2.1" in oid_str:
                new_vars.append((oid, rfc1902.Counter32(int(sim_val))))
            else:
                new_vars.append((oid, rfc1902.Integer(int(sim_val))))
        return new_vars

    def read_next_vars(self, var_binds, ac_info=(None, None)):
        new_vars = []
        for oid, val in var_binds:
            oid_str = str(oid)
            # [버그 수정] 정확히 인터페이스 베이스 OID일 때만 딱 한 번 .1 응답
            if oid_str == "1.3.6.1.2.1.2.2.1.2":
                next_oid = rfc1902.ObjectName("1.3.6.1.2.1.2.2.1.2.1")
                new_vars.append((next_oid, rfc1902.OctetString("Simulated-Eth0")))
                print(f"[*] WALK Request: {oid_str} -> Found Simulated-Eth0")
            else:
                # 그 외에는 종료를 알림 (이게 없으면 main.py가 무한 루프에 빠짐)
                new_vars.append((oid, rfc1902.EndOfMibView()))
        return new_vars

# 5. MibBuilder 생성 및 컨텍스트 등록
mib_builder = builder.MibBuilder()
chaos_instrum = ChaosMibInstrum(mib_builder)

try:
    snmp_context.unregister_context_name(b'')
except:
    pass

snmp_context.register_context_name(b'', chaos_instrum)
cmdrsp.GetCommandResponder(snmp_engine, snmp_context)

print("[*] Z-Net_Satut Chaos Agent started on 127.0.0.1:1161 (UDP)")
print("[*] Successfully handling WALK requests for interface discovery.")

async def run_agent():
    while True:
        await asyncio.sleep(1)

if __name__ == "__main__":
    try:
        asyncio.run(run_agent())
    except KeyboardInterrupt:
        print("\nAgent stopped by user.")