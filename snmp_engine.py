import asyncio
from pysnmp.hlapi.asyncio import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    get_cmd,next_cmd
)

class ZNetSatutEngineAsync:
    def __init__(self):
        self.snmp_engine = SnmpEngine()

    async def fetch_snmp(self, ip, port, oid, community, protocol='udp'):
        try:
            # 프로토콜 판단 (TCP가 정 안되면 UDP로 강제 전환)
            if protocol.lower() == 'tcp':
                try:
                    from pysnmp.hlapi.asyncio import TcpTransportTarget
                    transport = await TcpTransportTarget.create((ip, port), timeout=2.0, retries=1)
                except ImportError:
                    # TCP 지원 안되는 버전이면 UDP로 대체 시도
                    transport = await UdpTransportTarget.create((ip, port), timeout=2.0, retries=1)
            else:
                transport = await UdpTransportTarget.create((ip, port), timeout=2.0, retries=1)
            
            errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
                self.snmp_engine,
                CommunityData(community, mpModel=1),
                transport, 
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )

            result = {'ip': ip, 'oid': oid, 'value': None, 'status': 'Fail'}

            if errorIndication:
                result['value'] = str(errorIndication)
            elif errorStatus:
                result['value'] = f"{errorStatus.prettyPrint()}"
            else:
                for varBind in varBinds:
                    result['value'] = str(varBind[1])
                    result['status'] = 'Success'
                    
        except Exception as e:
            result = {'ip': ip, 'oid': oid, 'value': f"Conn Error: {str(e)}", 'status': 'Fail'}
        
        return result
    
    async def walk_interfaces(self, ip, port, community, protocol='udp'):
        """장비의 모든 네트워크 인터페이스 인덱스를 탐색합니다."""
        if protocol.lower() == 'tcp':
            from pysnmp.hlapi.asyncio import TcpTransportTarget
            transport = await TcpTransportTarget.create((ip, port), timeout=2.0, retries=1)
        else:
            transport = await UdpTransportTarget.create((ip, port), timeout=2.0, retries=1)

        interfaces = []
        # ifDescr (인터페이스 이름들) OID: 1.3.6.1.2.1.2.2.1.2
        gen = next_cmd(
            self.snmp_engine,
            CommunityData(community, mpModel=1),
            transport,
            ContextData(),
            ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.2'))
        )

        async for errorIndication, errorStatus, errorIndex, varBinds in gen:
            if errorIndication or errorStatus:
                break
            for varBind in varBinds:
                # 인덱스 번호 추출 및 이름 저장
                idx = varBind[0][-1]
                name = str(varBind[1])
                interfaces.append({'index': idx, 'name': name})
        
        return interfaces

    async def run_scan(self, targets):
        tasks = [self.fetch_snmp(t[0], t[1], t[2], t[3], t[4]) for t in targets]
        results = await asyncio.gather(*tasks)
        return results