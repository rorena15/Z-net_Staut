import sys
import asyncio
import warnings
from datetime import datetime

warnings.filterwarnings("ignore", category=DeprecationWarning)

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget, 
    QTableWidgetItem, QHeaderView, QTextEdit, QLabel, QSplitter, QMainWindow,
    QAbstractItemView, QComboBox, QStatusBar, QDialog, QFormLayout, QDialogButtonBox
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor, QFont

from snmp_engine import ZNetSatutEngineAsync
from db_manager import init_db, save_to_db
from config import TARGETS, DB_NAME, THRESHOLD
from library import get_oid_info
from styles import STYLESHEET

_SENTINEL = object()

class SettingsDialog(QDialog):
    def __init__(self, current_interval, parent=None):
        super().__init__(parent)
        self.setWindowTitle("환경 설정")
        self.setFixedSize(300, 150)
        self.setStyleSheet(STYLESHEET)
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setStyleSheet(self.styleSheet() + "QDialog { background-color: #1e1e1e; }")
        layout = QVBoxLayout(self)
        form_layout = QFormLayout()
        
        self.interval_combo = QComboBox()
        self.interval_combo.addItems(["10 Seconds", "30 Seconds", "60 Seconds"])
        
        idx = 0
        if current_interval == 30: idx = 1
        elif current_interval == 60: idx = 2
        self.interval_combo.setCurrentIndex(idx)
        
        form_layout.addRow("Polling Interval:", self.interval_combo)
        layout.addLayout(form_layout)
        
        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        layout.addWidget(self.button_box)

    def get_interval(self):
        return int(self.interval_combo.currentText().split()[0])

class MonitorWorker(QThread):
    update_data = Signal(list, str)
    log_msg = Signal(str)
    
    def __init__(self):
        super().__init__()
        self.is_running = False
        self._loop = None
        self.scan_interval = 10 

    def run(self):
        self.is_running = True
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._monitor_loop())

    def stop(self):
        self.is_running = False
    
    def set_interval(self, interval):
        self.scan_interval = interval

    async def _monitor_loop(self):
        engine = ZNetSatutEngineAsync()
        db_conn = init_db(DB_NAME)
        previous_data = {}

        self.log_msg.emit("[*] Z-Net_Satut 엔진 초기화 중...")
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

            for _ in range(self.scan_interval * 10):
                if not self.is_running: break
                await asyncio.sleep(0.1)

        db_conn.close()
        self.log_msg.emit("[*] 모니터링이 중지되었으며 DB가 안전하게 닫혔습니다.")

class ZNetSatutGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Z-VulnScan SecOps Monitor")
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

        top_layout = QHBoxLayout()
        self.start_btn = QPushButton("▶ 모니터링 시작")
        self.start_btn.clicked.connect(self.start_monitoring)
        
        self.stop_btn = QPushButton("■ 중지")
        self.stop_btn.clicked.connect(self.stop_monitoring)
        self.stop_btn.setEnabled(False)

        self.settings_btn = QPushButton("⚙️ 설정")
        self.settings_btn.clicked.connect(self.open_settings)

        top_layout.addWidget(self.start_btn)
        top_layout.addWidget(self.stop_btn)
        top_layout.addStretch()
        top_layout.addWidget(self.settings_btn)
        
        main_layout.addLayout(top_layout)

        splitter = QSplitter(Qt.Vertical)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels([
            "Target IP", "Metric Name", "Category", "Value", "Delta", "Status", "Security Intelligence"
        ])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionMode(QAbstractItemView.NoSelection)
        self.table.setFocusPolicy(Qt.NoFocus)

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
        splitter.setSizes([550, 150])
        main_layout.addWidget(splitter)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("상태: 대기 중")
        self.status_bar.setStyleSheet("color: #aaaaaa; font-weight: bold;")

    def open_settings(self):
        dialog = SettingsDialog(self.worker.scan_interval, self)
        if dialog.exec():
            new_interval = dialog.get_interval()
            self.worker.set_interval(new_interval)
            
            # 다음 스캔 시점부터 적용된다고 로그와 상태바에 명시
            self.append_log(f"[*] 환경설정: Polling Interval이 {new_interval}초로 변경되었습니다. (다음 스캔부터 적용)")
            if self.worker.isRunning():
                self.status_bar.showMessage(f"상태: 모니터링 동작 중 (LIVE) | 주기: {new_interval}초 (적용 대기 중...)")

    def start_monitoring(self):
        if not self.worker.isRunning():
            self.table.setRowCount(0)
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            # 설정 버튼은 모니터링 중에도 활성화 상태 유지
            
            self.status_bar.showMessage(f"상태: 모니터링 동작 중 (LIVE) | 주기: {self.worker.scan_interval}초")
            self.status_bar.setStyleSheet("color: #50fa7b; font-weight: bold;")
            self.worker.start()

    def stop_monitoring(self):
        if self.worker.isRunning():
            self.worker.stop()
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.status_bar.showMessage("상태: 모니터링 중지됨")
            self.status_bar.setStyleSheet("color: #ff5555; font-weight: bold;")

    def append_log(self, msg):
        time_str = datetime.now().strftime('%H:%M:%S')
        self.log_console.append(f"[{time_str}] {msg}")

    def update_table(self, results, scan_time):
        self.table.setRowCount(0)
        # 스캔이 완료되어 테이블이 업데이트될 때 "적용 대기 중" 메시지가 자연스럽게 사라짐
        self.status_bar.showMessage(f"상태: 모니터링 동작 중 (LIVE) | 주기: {self.worker.scan_interval}초 | 최근 스캔: {scan_time}")

        for row, res in enumerate(results):
            self.table.insertRow(row)
            info = get_oid_info(res['oid'])
            delta = res.get('delta')

            val_str = str(res['value']) if res['value'] is not None else '-'
            delta_str = '-' if (delta is None or delta == '-') else str(delta)

            is_online = (res.get('status') == 'Success')

            ip_item = QTableWidgetItem(res['ip'])
            name_item = QTableWidgetItem(info['name'])
            cat_item = QTableWidgetItem(info['category'])
            val_item = QTableWidgetItem(val_str)
            
            delta_item = QTableWidgetItem(delta_str)
            delta_item.setTextAlignment(Qt.AlignCenter)

            status_item = QTableWidgetItem()
            status_item.setTextAlignment(Qt.AlignCenter)
            font = QFont()
            font.setBold(True)
            status_item.setFont(font)

            intel_item = QTableWidgetItem()

            if is_online:
                status_item.setText("ONLINE")
                status_item.setForeground(QColor("#50fa7b"))
                
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
                status_item.setForeground(QColor("#ff5555"))
                
                dim_color = QColor("#666666")
                ip_item.setForeground(dim_color)
                name_item.setForeground(dim_color)
                cat_item.setForeground(dim_color)
                val_item.setForeground(dim_color)
                delta_item.setForeground(dim_color)
                
                intel_item.setText("[N/A]")
                intel_item.setForeground(dim_color)

            self.table.setItem(row, 0, ip_item)
            self.table.setItem(row, 1, name_item)
            self.table.setItem(row, 2, cat_item)
            self.table.setItem(row, 3, val_item)
            self.table.setItem(row, 4, delta_item)
            self.table.setItem(row, 5, status_item)
            self.table.setItem(row, 6, intel_item)