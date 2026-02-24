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
from chaos_simulator import get_simulated_value

# 1. SNMP 엔진 설정
snmp_engine = engine.SnmpEngine()

# 2. 전송 계층 설정 (UDP 1161)
config.add_transport(
    snmp_engine,
    udp.DOMAIN_NAME,
    udp.UdpAsyncioTransport().open_server_mode(('127.0.0.1', 1161))
)

# 3. SNMP 커뮤니티 및 보안 설정 (public)
config.add_v1_system(snmp_engine, 'my-area', 'public')

# 4. SNMP 컨텍스트 생성 (이때 내부적으로 b''가 자동 등록됨)
snmp_context = context.SnmpContext(snmp_engine)

# 시뮬레이션 시작 시간 기록
start_time = time.time()

# 5. 요청 처리 핸들러
class ChaosMibInstrum(instrum.MibInstrumController):
    def read_vars(self, var_binds, ac_info=(None, None)):
        new_var_binds = []
        for oid, val in var_binds:
            oid_str = str(oid)
            # chaos_simulator 로직 연결
            sim_val = get_simulated_value(oid_str, start_time)
            
            from pysnmp.proto import rfc1902
            # 트래픽 데이터(1.3.6.1.2.1.2.2.1 계열)는 Counter32, 나머지는 Integer 응답
            if "1.3.6.1.2.1.2.2.1" in oid_str:
                new_var_binds.append((oid, rfc1902.Counter32(int(sim_val))))
            else:
                new_var_binds.append((oid, rfc1902.Integer(int(sim_val))))
        return new_var_binds

# 6. MibBuilder 생성 및 컨트롤러 준비
mib_builder = builder.MibBuilder()
chaos_instrum = ChaosMibInstrum(mib_builder)

# 7. [중요] 중복 컨텍스트 에러 해결: 기존 자동 등록된 b''를 제거 후 재등록
try:
    snmp_context.unregister_context_name(b'')
except Exception:
    pass # 혹시 등록되어 있지 않은 경우 예외 처리

snmp_context.register_context_name(b'', chaos_instrum)
cmdrsp.GetCommandResponder(snmp_engine, snmp_context)

print("[*] Z-Net_Satut Chaos Agent started on 127.0.0.1:1161 (UDP)")
print("[*] Successfully replaced default context with Chaos Agent")

# 8. 비동기 루프 실행
async def run_agent():
    while True:
        await asyncio.sleep(1)

if __name__ == "__main__":
    try:
        asyncio.run(run_agent())
    except KeyboardInterrupt:
        print("\nAgent stopped by user.")