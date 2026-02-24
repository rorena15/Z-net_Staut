import asyncio
import time
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.carrier.asyncio.stream import tcp
from chaos_simulator import get_simulated_value

# 1. SNMP 엔진 및 전송 계층 설정
snmp_engine = engine.SnmpEngine()

# config.py의 로컬 테스트 설정(127.0.0.1, 1161, tcp)과 일치시켜야 함
config.addTransport(
    snmp_engine,
    tcp.domainName,
    tcp.TcpTransport().openServerMode(('127.0.0.1', 1161))
)

# 2. SNMP 커뮤니티 및 보안 설정 (public)
config.addV1System(snmp_engine, 'my-area', 'public')
snmp_context = context.SnmpContext(snmp_engine)

# 시뮬레이션 시작 시간 기록
start_time = time.time()

# 3. 요청 처리 핸들러 (chaos_simulator 로직 연결)
class ChaosMibInstrum(cmdrsp.MibInstrumController):
    def readVars(self, varBinds, acInfo=(None, None)):
        new_varBinds = []
        for oid, val in varBinds:
            oid_str = str(oid)
            # 제시하신 chaos_simulator의 로직으로 값 생성
            sim_val = get_simulated_value(oid_str, start_time)
            
            from pysnmp.proto import rfc1902
            # 트래픽 데이터는 Counter32, 나머지는 Integer 등으로 응답
            if "1.3.6.1.2.1.2.2.1" in oid_str:
                new_varBinds.append((oid, rfc1902.Counter32(sim_val)))
            else:
                new_varBinds.append((oid, rfc1902.Integer(sim_val)))
        return new_varBinds

snmp_context.registerContextName(b'', ChaosMibInstrum())
cmdrsp.GetCommandResponder(snmp_engine, snmp_context)

print("[*] Z-Net_Satut Chaos Agent started on 127.0.0.1:1161 (TCP)")
print("[*] Monitoring chaos_simulator scenarios...")

loop = asyncio.get_event_loop()
try:
    loop.run_forever()
except KeyboardInterrupt:
    pass