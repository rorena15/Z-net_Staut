import sys
import asyncio
import warnings
import time
import numpy as np
import pyqtgraph as pg
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
                if res['status'] != 'Success' or res['value'] is None:
                    res['delta'] = '-'
                    continue
                
                try:
                    curr_val = int(res['value'])
                    prev = previous_data.get(key, _SENTINEL)
                    
                    if prev is _SENTINEL:
                        res['delta'] = None
                    else:
                        # [핵심 수정] OID나 명칭에 따라 Delta 계산 방식 분리
                        # TCP 세션(1.3.6.1.2.1.6.9.0) 등 Gauge 타입은 단순 차이만 계산
                        if "1.6.9.0" in res['oid']:
                            res['delta'] = curr_val - prev # 줄어들면 마이너스(-) 값이 나옴
                        
                        # 트래픽(Octets) 등 Counter 타입은 역전(Wrap) 로직 적용
                        else:
                            if curr_val >= prev:
                                res['delta'] = curr_val - prev
                            else:
                                # Counter가 최대값(2^32-1)을 찍고 0으로 돌아갔을 때 처리
                                res['delta'] = (4294967295 - prev) + curr_val + 1
                    
                    previous_data[key] = curr_val
                except (ValueError, TypeError):
                    res['delta'] = '-'

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
        self.resize(1300, 900)
        self.setStyleSheet(STYLESHEET)
        
        # [신규] 분석용 데이터 저장소
        self.history_data = {}
        self.max_history = 180
        self.current_selected_key = None

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

        # 테이블 설정
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["Target IP", "Metric Name", "Category", "Value", "Delta", "Status", "Security Intelligence"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setFocusPolicy(Qt.NoFocus)
        self.table.itemClicked.connect(self.on_item_selected)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
        for i, w in enumerate([150, 180, 120, 150, 100, 100]):
            self.table.setColumnWidth(i, w)

        # [기능 1] 실시간 그래프 영역 추가
        date_axis = pg.DateAxisItem(orientation='bottom')
        self.plot_widget = pg.PlotWidget(
            title="Real-time Traffic Trend",
            axisItems={'bottom': date_axis} # 시간 축 적용
        )
        self.plot_widget.setBackground('#101010')
        self.plot_widget.showGrid(x=True, y=True, alpha=0.3)
        self.plot_curve = self.plot_widget.plot(pen=pg.mkPen(color='#50fa7b', width=2))
        
        self.log_console = QTextEdit()
        self.log_console.setReadOnly(True)

        splitter.addWidget(self.table)
        splitter.addWidget(self.plot_widget) # 테이블 아래 그래프 배치
        splitter.addWidget(self.log_console)
        splitter.setSizes([450, 250, 150])
        main_layout.addWidget(splitter)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("상태: 대기 중")

    def on_item_selected(self, item):
        row = item.row()
        ip = self.table.item(row, 0).text()
        metric = self.table.item(row, 1).text()
        category = self.table.item(row, 2).text() # 카테고리(Traffic 등) 가져오기
        self.current_selected_key = f"{ip}_{metric}"
        # [수정] 카테고리에 따라 Y축 단위 설정
        if category == "Traffic":
            # units='B'를 주면 1024 단위로 K, M, G를 자동 계산해줍니다.
            self.plot_widget.setLabel('left', 'Traffic', units='B')
        else:
            # 세션 수 등은 단위를 비워서 지수 표기법만 방지
            self.plot_widget.setLabel('left', 'Count', units='')
        self.update_plot()
        

    def update_plot(self):
        if self.current_selected_key in self.history_data:
            data_points = self.history_data[self.current_selected_key]
            if not data_points: return
            
            # x축(시간)과 y축(값) 리스트로 분리
            x = [pt[0] for pt in data_points]
            y = [pt[1] for pt in data_points]
            
            self.plot_curve.setData(x, y) # 시간과 값을 동시에 전달
            self.plot_widget.setTitle(f"Trend Analysis: {self.current_selected_key}")

    def open_settings(self):
        dialog = SettingsDialog(self.worker.scan_interval, self)
        if dialog.exec():
            new_interval = dialog.get_interval()
            self.worker.set_interval(new_interval)
            self.append_log(f"[*] 환경설정: 주기 {new_interval}초 변경 (다음 스캔부터 적용)")

    def start_monitoring(self):
        if not self.worker.isRunning():
            # [1] UI 및 메모리 데이터 즉시 초기화
            self.table.setRowCount(0)
            self.log_console.clear()
            self.history_data.clear() 
            self.plot_curve.setData([]) 
            self.current_selected_key = None
            
            # [2] DB 초기화 (테이블 이름 불일치 수정: snmp_metrics)
            try:
                import sqlite3
                conn = sqlite3.connect(DB_NAME)
                cursor = conn.cursor()
                # db_manager.py에 정의된 테이블 이름인 snmp_metrics로 수정
                cursor.execute("DELETE FROM snmp_metrics WHERE ip = '127.0.0.1'")
                conn.commit()
                conn.close()
                self.append_log("[*] 시뮬레이션 타겟(127.0.0.1)의 DB 이력을 초기화했습니다.")
            except Exception as e:
                self.append_log(f"[*] 알림: 초기 데이터 정리 건너뜀 ({e})")

            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.status_bar.setStyleSheet("color: #50fa7b; font-weight: bold;")
            
            self.worker.start()

    def stop_monitoring(self):
        if self.worker.isRunning():
            self.worker.stop()
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)

    def append_log(self, msg):
        self.log_console.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

    def update_table(self, results, scan_time):
        self.table.setRowCount(0)
        self.status_bar.showMessage(f"상태: LIVE | 주기: {self.worker.scan_interval}s | 최근 스캔: {scan_time}")
        
        results.sort(key=lambda x: (
            # IP 주소(127.0.0.1)는 127.000.000.001 형태로 변환하여 숫자 순서 유지
            # 도메인 주소(demo.pysnmp.com)는 문자열 그대로 사용하여 비교 가능하게 함
            ".".join(p.zfill(3) for p in x['ip'].split('.')) if all(p.isdigit() for p in x['ip'].split('.') if p) else x['ip'],
            # 2순위: 메트릭 이름 기준 정렬
            get_oid_info(x['oid'])['name']
        ))
        current_ts = time.time()
        for row, res in enumerate(results):
            self.table.insertRow(row)
            info = get_oid_info(res['oid'])
            delta = res.get('delta')
            key = f"{res['ip']}_{info['name']}"

            # 히스토리 데이터 축적
            if isinstance(delta, int):
                if key not in self.history_data: self.history_data[key] = []
                self.history_data[key].append((current_ts, delta))
                if len(self.history_data[key]) > self.max_history: self.history_data[key].pop(0)

            # [보안 분석 로직] 안내 메시지 형식 통일
            intel_text, intel_color = "[NORMAL]", QColor("#50fa7b")
            
            if isinstance(delta, int):
                is_alert = False
                alert_msg = info.get('alert_context', '이상 징후 탐지') # library.py의 메세지 활용
                
                # [1] 절대 임계치 체크 (config.py 기준)
                for th_key, limit in THRESHOLD.items():
                    if th_key.lower() in info['name'].lower() and delta >= limit:
                        intel_text = f"[CRITICAL] {alert_msg}" # 메시지 형식 통일
                        intel_color = QColor("#ff5555")
                        is_alert = True
                        break
                
                # [2] 동적 스파이크 체크 (평균 대비 5배)
                if not is_alert and len(self.history_data.get(key, [])) >= 5:
                    # [수정] 튜플 리스트에서 값(delta)만 추출하여 평균 계산
                    history_values = [pt[1] for pt in self.history_data[key][:-1]]
                    avg_val = np.mean(history_values)
                    
                    # Delta가 4GB 근처라면 시뮬레이션 노이즈에 의한 역전 현상으로 간주하여 무시
                    if delta > 4000000000: 
                        intel_text = "[LEARNING]" 
                        intel_color = QColor("#888888")
                    elif avg_val > 1048576 and delta > avg_val * 5:
                        intel_text = f"[CRITICAL] {alert_msg}"
                        intel_color = QColor("#ffb86c")
                        is_alert = True
            else:
                intel_text = "[N/A]"
                intel_color = QColor("#888888")

            # 가독성 높은 단위 변환 출력 적용
            is_online = (res.get('status') == 'Success')
            val_display = self.format_value(res['value'], info['category']) if is_online else "-"
            delta_display = self.format_value(delta, info['category']) if isinstance(delta, int) else "-"

            row_items = [
                QTableWidgetItem(res['ip']),
                QTableWidgetItem(info['name']),
                QTableWidgetItem(info['category']),
                QTableWidgetItem(val_display),
                QTableWidgetItem(delta_display),
                QTableWidgetItem("ONLINE" if is_online else "OFFLINE"),
                QTableWidgetItem(intel_text)
            ]

            # 스타일: ONLINE/OFFLINE 강조 및 알림 색상 적용
            font = QFont(); font.setBold(True)
            row_items[5].setFont(font)
            row_items[5].setForeground(QColor("#50fa7b") if is_online else QColor("#ff5555"))
            row_items[6].setForeground(intel_color)

            # 오프라인 시 행 전체 어둡게 처리
            if not is_online:
                for i in range(5): row_items[i].setForeground(QColor("#666666"))

            for col, item in enumerate(row_items):
                if col in [4, 5]: item.setTextAlignment(Qt.AlignCenter)
                self.table.setItem(row, col, item)

        self.update_plot()
        
    def format_value(self, value, category):
        """숫자를 가독성 좋은 단위로 변환 (Traffic은 B/KB/MB/GB, 나머지는 콤마 처리)"""
        if not isinstance(value, (int, float)):
            return str(value)
        
        # 1. 트래픽 데이터 (Byte 단위) 처리
        if category == "Traffic":
            for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                if abs(value) < 1024.0:
                    return f"{value:3.2f} {unit}"
                value /= 1024.0
            return f"{value:.2f} PB"
        
        # 2. 일반 세션/카운트 데이터 (천 단위 콤마)
        return f"{int(value):,}"