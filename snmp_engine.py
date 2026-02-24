import asyncio
from pysnmp.hlapi.asyncio import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    get_cmd,
)

class ZNetSatutEngineAsync:
    def __init__(self):
        self.snmp_engine = SnmpEngine()

    async def fetch_snmp(self, ip, port, oid, community):
        transport = await UdpTransportTarget.create((ip, port))
        
        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            self.snmp_engine,
            CommunityData(community, mpModel=1),
            transport, 
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )

        result = {
            'ip': ip,
            'oid': oid,
            'value': None,
            'status': 'Fail'
        }

        if errorIndication:
            result['value'] = str(errorIndication)
        elif errorStatus:
            result['value'] = f"{errorStatus.prettyPrint()} at {errorIndex}"
        else:
            for varBind in varBinds:
                result['value'] = str(varBind[1])
                result['status'] = 'Success'
        
        return result

    async def run_scan(self, targets):
        tasks = [self.fetch_snmp(ip, port, oid, comm) for ip, port, oid, comm in targets]
        results = await asyncio.gather(*tasks)
        return results