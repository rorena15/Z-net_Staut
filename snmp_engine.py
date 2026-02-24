# snmp_engine.py
import asyncio
from pysnmp.hlapi.asyncio import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    get_cmd,
    next_cmd,
)

# ────────────────────────────────────────────────────────────────
# [BUG FIX #2] NoSuchObject / NoSuchInstance 타입 체크 추가
#
# 원인: str(varBind[1])은 NoSuchObject도 문자열로 변환해버림.
#       → status='Success'로 기록되지만 value는 의미없는 문자열.
#       → main.py에서 int() 변환 실패 → delta='-' → CRITICAL 미탐.
# ────────────────────────────────────────────────────────────────
try:
    from pysnmp.proto.rfc1905 import NoSuchObject, NoSuchInstance, EndOfMibView
except ImportError:
    # pysnmp 버전에 따라 위치가 다를 수 있음
    from pysnmp.proto.api.v2c import NoSuchObject, NoSuchInstance, EndOfMibView


class ZNetSatutEngineAsync:
    def __init__(self):
        self.snmp_engine = SnmpEngine()

    async def _make_transport(self, ip, port, protocol):
        """프로토콜에 따른 Transport 생성. TCP 미지원 시 UDP 폴백."""
        if protocol.lower() == 'tcp':
            try:
                from pysnmp.hlapi.asyncio import TcpTransportTarget
                return await TcpTransportTarget.create((ip, port), timeout=2.0, retries=1)
            except (ImportError, Exception):
                pass
        return await UdpTransportTarget.create((ip, port), timeout=2.0, retries=1)

    async def fetch_snmp(self, ip, port, oid, community, protocol='udp'):
        result = {'ip': ip, 'oid': oid, 'value': None, 'status': 'Fail'}

        try:
            transport = await self._make_transport(ip, port, protocol)

            errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
                self.snmp_engine,
                CommunityData(community, mpModel=1),
                transport,
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )

            if errorIndication:
                result['value'] = str(errorIndication)
                return result

            if errorStatus:
                result['value'] = errorStatus.prettyPrint()
                return result

            # ── [BUG FIX #2] 타입 체크 ──────────────────────────
            for varBind in varBinds:
                resp_val = varBind[1]

                if isinstance(resp_val, NoSuchObject):
                    result['value'] = "NoSuchObject"
                    result['status'] = 'Fail'
                    return result

                if isinstance(resp_val, NoSuchInstance):
                    result['value'] = "NoSuchInstance"
                    result['status'] = 'Fail'
                    return result

                if isinstance(resp_val, EndOfMibView):
                    result['value'] = "EndOfMibView"
                    result['status'] = 'Fail'
                    return result

                # 정상 값: 숫자 변환 시도, 실패 시 문자열 보존
                try:
                    result['value'] = int(resp_val)
                except (TypeError, ValueError):
                    result['value'] = str(resp_val)

                result['status'] = 'Success'
            # ─────────────────────────────────────────────────────

        except Exception as e:
            result['value'] = f"Conn Error: {str(e)}"

        return result

    async def walk_interfaces(self, ip, port, community, protocol='udp'):
        """
        장비의 모든 네트워크 인터페이스 인덱스를 탐색.

        [BUG FIX #2 연속] pysnmp 5.x의 next_cmd는 async generator가 아닌
        단일 코루틴임. 'async for'가 아닌 루프로 직접 반복 호출해야 함.
        """
        interfaces = []
        current_oid = '1.3.6.1.2.1.2.2.1.2'   # ifDescr 베이스 OID
        base_prefix  = '1.3.6.1.2.1.2.2.1.2'

        try:
            transport = await self._make_transport(ip, port, protocol)
        except Exception as e:
            print(f"[!] Transport 생성 실패 ({ip}): {e}")
            return interfaces

        while True:
            try:
                errorIndication, errorStatus, errorIndex, varBinds = await next_cmd(
                    self.snmp_engine,
                    CommunityData(community, mpModel=1),
                    transport,
                    ContextData(),
                    ObjectType(ObjectIdentity(current_oid))
                )
            except Exception as e:
                print(f"[!] WALK 오류 ({ip}): {e}")
                break

            if errorIndication or errorStatus:
                break

            if not varBinds:
                break

            for varBind in varBinds:
                resp_oid = str(varBind[0])
                resp_val = varBind[1]

                # ifDescr 범위를 벗어나면 WALK 종료
                if not resp_oid.startswith(base_prefix):
                    return interfaces

                if isinstance(resp_val, EndOfMibView):
                    return interfaces

                # 인덱스: OID 마지막 숫자
                try:
                    idx = int(str(varBind[0])[-1])
                except ValueError:
                    idx = len(interfaces) + 1

                interfaces.append({'index': idx, 'name': str(resp_val)})
                current_oid = resp_oid   # 다음 GETNEXT 시작점 갱신

        return interfaces

    async def run_scan(self, targets):
        tasks = [
            self.fetch_snmp(t[0], t[1], t[2], t[3], t[4])
            for t in targets
        ]
        return list(await asyncio.gather(*tasks))