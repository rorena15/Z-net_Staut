from fastapi import FastAPI
import uvicorn
from pydantic import BaseModel
import subprocess
import os
import time  # [추가] 시간 계산용

app = FastAPI(title="Z-Core Middleware API")

class AlertPayload(BaseModel):
    source: str
    target_ip: str
    alert_type: str
    value: str
    message: str

# [추가] IP별 마지막 스캔 실행 시간을 저장하는 딕셔너리
scan_cooldowns = {}
COOLDOWN_SECONDS = 300  # 쿨타임: 5분 (필요에 따라 조절하세요)

@app.post("/api/v1/alert")
async def receive_alert(payload: AlertPayload):
    current_time = time.time()
    target_ip = payload.target_ip
    
    # -------------------------------------------------------------
    # [추가] 쿨타임 체크 로직
    # 이미 딕셔너리에 IP가 있고, 지정된 시간이 지나지 않았다면 무시
    if target_ip in scan_cooldowns:
        elapsed = current_time - scan_cooldowns[target_ip]
        if elapsed < COOLDOWN_SECONDS:
            print(f"[-] {target_ip}는 이미 스캔이 진행 중입니다. (쿨타임 {int(COOLDOWN_SECONDS - elapsed)}초 남음)")
            return {"status": "ignored", "reason": "cooldown_active"}
    # -------------------------------------------------------------

    print(f"\n[+] 위협 경보 수신! 대상 IP: {target_ip}")
    print(f"    - 내용: {payload.message}")
    
    # 쿨타임 갱신 (현재 시간 저장)
    scan_cooldowns[target_ip] = current_time
    
    # 스캔 실행
    trigger_vulnscan(target_ip)
    
    return {"status": "success", "action": "scan_triggered"}

def trigger_vulnscan(ip: str):
    # 본인 환경에 맞는 경로로 꼭 유지하세요!
    vulnscan_main_path = os.path.abspath("../Z-V_Scan/scanner_engine/main.py")
    
    print(f"[*] Z-VulnScan에게 {ip} 긴급 취약점 진단 명령 전송 중...\n")
    try:
        subprocess.Popen(["python", vulnscan_main_path, "--target", ip])
    except Exception as e:
        print(f"[!] Z-VulnScan 실행 실패: {e}")
        
vulnerable_ips = set()

class VulnReportPayload(BaseModel):
    target_ip: str
    vuln_count: int

@app.post("/api/v1/vuln_report")
async def receive_vuln_report(payload: VulnReportPayload):
    if payload.vuln_count > 0:
        vulnerable_ips.add(payload.target_ip)
        print(f"\n[!] Z-VulnScan 보고: {payload.target_ip}에서 {payload.vuln_count}개의 취약점 발견!")
        print(f"[*] 해당 IP를 '집중 감시(High Risk)' 대상으로 등록합니다.")
    return {"status": "success"}

@app.get("/api/v1/vulnerable_ips")
async def get_vulnerable_ips():
    return {"vulnerable_ips": list(vulnerable_ips)}
if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8090)