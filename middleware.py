from fastapi import FastAPI, Request
import uvicorn
from pydantic import BaseModel

app = FastAPI(title="Z-Core Middleware API")

class AlertPayload(BaseModel):
    source: str
    target_ip: str
    alert_type: str
    value: str
    message: str

@app.post("/api/v1/alert")
async def receive_alert(payload: AlertPayload):
    # Satut에서 넘어온 CRITICAL 알람 수신
    print(f"\n[+] 위협 경보 수신! 대상 IP: {payload.target_ip}")
    print(f"    - 내용: {payload.message}")
    
    # TODO: Z-VulnScan의 스캔 API를 호출하거나 큐(Queue)에 작업 등록
    trigger_vulnscan(payload.target_ip)
    
    return {"status": "success", "action": "scan_triggered"}

def trigger_vulnscan(ip: str):
    # 추후 Z-VulnScan과 통신할 로직
    print(f"[*] Z-VulnScan에게 {ip} 긴급 취약점 진단 명령 전송 중...\n")

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8090)