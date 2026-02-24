import sys
import asyncio
import warnings
from datetime import datetime

warnings.filterwarnings("ignore", category=DeprecationWarning)

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget, 
    QTableWidgetItem, QHeaderView, QTextEdit, QLabel, QSplitter, QMainWindow,QAbstractItemView
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor,QFont

from snmp_engine import ZNetSatutEngineAsync
from db_manager import init_db, save_to_db
from config import TARGETS, DB_NAME, SCAN_INTERVAL, THRESHOLD
from library import get_oid_info
from styles import STYLESHEET

_SENTINEL = object()

class MonitorWorker(QThread):
    update_data = Signal(list, str)
    log_msg = Signal(str)
    
    def __init__(self):
        super().__init__()
        self.is_running = False
        self._loop = None

    def run(self):
        self.is_running = True
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._monitor_loop())

    def stop(self):
        self.is_running = False
    
    async def _monitor_loop(self):
        engine = ZNetSatutEngineAsync()
        db_conn = init_db(DB_NAME)
        previous_data = {}

        self.log_msg.emit("[*] Z-Net_Satut 엔진 초기화 및 인터페이스 탐색 중...")
        dynamic_targets = list(TARGETS)
        seen_ips = set()

        for target in TARGETS:
            if not self.is_running: break
            ip, port, oid, comm, proto = target
            if ip in seen_ips or "1.1.1.0" not in oid:
                continue
            seen_ips.add(ip)
            
            try:
                ifaces = await engine.walk_interfaces(ip, port, comm, proto)
                for iface in ifaces:
                    idx = iface['index']
                    dynamic_targets.append((ip, port, f"1.3.6.1.2.1.2.2.1.10.{idx}", comm, proto))
                    dynamic_targets.append((ip, port, f"1.3.6.1.2.1.2.2.1.16.{idx}", comm, proto))
                self.log_msg.emit(f"[*] {ip} - {len(ifaces)}개 인터페이스 자동 매핑 완료")
            except Exception as e:
                self.log_msg.emit(f"[!] {ip} 인터페이스 탐색 실패: {e}")

        self.log_msg.emit("[*] 실시간 모니터링을 시작합니다.")

        while self.is_running:
            scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            results = await engine.run_scan(dynamic_targets)

            for res in results:
                key = f"{res['ip']}_{res['oid']}"
                if res['status'] != 'Success':
                    res['delta'] = '-'
                    continue
                try:
                    current_val = int(res['value'])
                except (ValueError, TypeError):
                    res['delta'] = '-'
                    continue

                prev = previous_data.get(key, _SENTINEL)
                if prev is _SENTINEL:
                    res['delta'] = None
                elif current_val >= prev:
                    res['delta'] = current_val - prev
                else:
                    res['delta'] = (4_294_967_295 - prev) + current_val + 1
                previous_data[key] = current_val

            save_to_db(db_conn, results)
            self.update_data.emit(results, scan_time)

            for _ in range(SCAN_INTERVAL * 10):
                if not self.is_running: break
                await asyncio.sleep(0.1)

        db_conn.close()
        self.log_msg.emit("[*] 모니터링이 중지되었으며 DB가 안전하게 닫혔습니다.")

class ZNetSatutGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Z-Net_Satut SecOps Monitor")
        self.resize(1300, 800)
        self.setStyleSheet(STYLESHEET)
        
        self.worker = MonitorWorker()
        self.worker.update_data.connect(self.update_table)
        self.worker.log_msg.connect(self.append_log)

        self.init_ui()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        control_layout = QHBoxLayout()
        self.status_label = QLabel("상태: 대기 중")
        self.status_label.setStyleSheet("color: #aaaaaa; font-weight: bold;")
        
        self.start_btn = QPushButton("▶ 모니터링 시작")
        self.start_btn.clicked.connect(self.start_monitoring)
        
        self.stop_btn = QPushButton("■ 모니터링 중지")
        self.stop_btn.clicked.connect(self.stop_monitoring)
        self.stop_btn.setEnabled(False)

        control_layout.addWidget(self.status_label)
        control_layout.addStretch()
        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.stop_btn)
        main_layout.addLayout(control_layout)

        splitter = QSplitter(Qt.Vertical)

        self.table = QTableWidget(0, 7)
        self.table.verticalHeader().setVisible(False)                 # 행 번호 숨기기
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)  # 더블클릭 수정 방지
        self.table.setSelectionMode(QAbstractItemView.NoSelection)    # 클릭 및 드래그 선택 방지
        self.table.setFocusPolicy(Qt.NoFocus)                         # 클릭 시 점선 테두리 생기는 현상 방지
        self.table.setHorizontalHeaderLabels([
            "Target IP", "Metric Name", "Category", "Value", "Delta", "Status", "Security Intelligence"
        ])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
        self.table.setColumnWidth(0, 150)
        self.table.setColumnWidth(1, 180)
        self.table.setColumnWidth(2, 120)
        self.table.setColumnWidth(3, 150)
        self.table.setColumnWidth(4, 100)
        self.table.setColumnWidth(5, 100)
        
        self.log_console = QTextEdit()
        self.log_console.setReadOnly(True)
        self.log_console.setPlaceholderText("시스템 로그 대기 중...")

        splitter.addWidget(self.table)
        splitter.addWidget(self.log_console)
        splitter.setSizes([500, 200])
        main_layout.addWidget(splitter)

    def start_monitoring(self):
        if not self.worker.isRunning():
            self.table.setRowCount(0)
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.status_label.setText("상태: 모니터링 동작 중 (LIVE)")
            self.status_label.setStyleSheet("color: #50fa7b; font-weight: bold;")
            self.worker.start()

    def stop_monitoring(self):
        if self.worker.isRunning():
            self.worker.stop()
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.status_label.setText("상태: 모니터링 중지됨")
            self.status_label.setStyleSheet("color: #ff5555; font-weight: bold;")

    def append_log(self, msg):
        time_str = datetime.now().strftime('%H:%M:%S')
        self.log_console.append(f"[{time_str}] {msg}")

    def update_table(self, results, scan_time):
        self.table.setRowCount(0)
        self.status_label.setText(f"상태: 모니터링 동작 중 (LIVE) | 최근 스캔: {scan_time}")

        for row, res in enumerate(results):
            self.table.insertRow(row)
            info = get_oid_info(res['oid'])
            delta = res.get('delta')

            val_str = str(res['value']) if res['value'] is not None else '-'
            delta_str = '-' if (delta is None or delta == '-') else str(delta)

            is_online = (res.get('status') == 'Success')

            # 1. 각 셀 아이템 기본 생성
            ip_item = QTableWidgetItem(res['ip'])
            name_item = QTableWidgetItem(info['name'])
            cat_item = QTableWidgetItem(info['category'])
            val_item = QTableWidgetItem(val_str)
            
            delta_item = QTableWidgetItem(delta_str)
            delta_item.setTextAlignment(Qt.AlignCenter)

            status_item = QTableWidgetItem()
            status_item.setTextAlignment(Qt.AlignCenter)
            
            # Status 폰트를 굵게(Bold) 설정하여 시인성 강화
            font = QFont()
            font.setBold(True)
            status_item.setFont(font)

            intel_item = QTableWidgetItem()

            # 2. ONLINE / OFFLINE 에 따른 시각적 차별화
            if is_online:
                status_item.setText("ONLINE")
                status_item.setForeground(QColor("#50fa7b")) # 눈에 띄는 밝은 녹색
                
                # 인텔리전스 로직 (온라인일 때만 정상 분석)
                if isinstance(delta, int):
                    if info['name'].startswith("SysUpTime") and delta < 0:
                        intel_item.setText(f"[ALERT] {info.get('alert_context', '장비 상태 변화 감지')}")
                        intel_item.setForeground(QColor("#ffb86c"))
                    else:
                        is_critical = False
                        for key, limit in THRESHOLD.items():
                            if key in info['name'] and delta >= limit:
                                is_critical = True
                                intel_item.setText(f"[CRITICAL] {info.get('alert_context', '이상 징후 발생')}")
                                intel_item.setForeground(QColor("#ff5555"))
                                break
                        if not is_critical:
                            intel_item.setText("[NORMAL]")
                            intel_item.setForeground(QColor("#50fa7b"))
                else:
                    intel_item.setText("[N/A]")
                    intel_item.setForeground(QColor("#888888"))
            else:
                status_item.setText("OFFLINE")
                status_item.setForeground(QColor("#ff5555")) # 경고성 빨간색
                
                # [핵심] 오프라인일 경우 해당 행의 나머지 글씨를 모두 어두운 회색으로 변경
                dim_color = QColor("#666666")
                ip_item.setForeground(dim_color)
                name_item.setForeground(dim_color)
                cat_item.setForeground(dim_color)
                val_item.setForeground(dim_color)
                delta_item.setForeground(dim_color)
                
                intel_item.setText("[N/A]")
                intel_item.setForeground(dim_color)

            # 3. 테이블에 아이템 배치
            self.table.setItem(row, 0, ip_item)
            self.table.setItem(row, 1, name_item)
            self.table.setItem(row, 2, cat_item)
            self.table.setItem(row, 3, val_item)
            self.table.setItem(row, 4, delta_item)
            self.table.setItem(row, 5, status_item)
            self.table.setItem(row, 6, intel_item)