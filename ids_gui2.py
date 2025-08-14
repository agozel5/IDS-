# ids_full_turkce.py
import sys
import threading
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta
import time

import psutil
import requests
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNSQR

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QTableWidget,
    QTableWidgetItem, QHBoxLayout, QFileDialog, QComboBox, QMessageBox, QCheckBox,
    QLineEdit, QHeaderView, QAbstractItemView, QTabWidget
)
from PyQt5.QtCore import pyqtSignal, QThread, Qt
from PyQt5.QtGui import QFont, QIcon, QColor, QBrush

from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure


# ---------------------------
# Sniffer Thread - Paket yakalama ve tespit
# ---------------------------
class SnifferThread(QThread):
    packet_signal = pyqtSignal(dict)   # dict ile yapılandırılmış paket bilgisi gönderir
    stats_signal = pyqtSignal(dict)    # trafik istatistikleri

    def __init__(self, interface, alert_only, signature_rules):
        super().__init__()
        self.interface = interface
        self.alert_only = alert_only
        self.running = False
        self.traffic_stats = defaultdict(int)
        self.buffer_lock = threading.Lock()
        self.signature_rules = signature_rules

        # Anomali / durum veri yapıları
        self.syn_counts = defaultdict(deque)   # src -> deque of timestamps (SYN to port 22 dedektörü, genel SYN dedektörü)
        self.ip_rate = defaultdict(deque)     # src -> deque of (timestamp, bytes)
        self.ssh_syn_threshold = 10           # kısa süre içinde SSH portuna çok sayıda SYN => brute force
        self.ssh_window_seconds = 20

    def run(self):
        self.running = True
        last_emit = time.time()
        while self.running:
            try:
                sniff(prn=self.process_packet, store=False, timeout=1, iface=self.interface)
            except Exception as e:
                print("sniff error:", e)
            if time.time() - last_emit >= 0.5:
                self.stats_signal.emit(dict(self.traffic_stats))
                last_emit = time.time()

    def stop(self):
        self.running = False
        self.wait()

    def _mark_traffic(self, pkt):
        self.traffic_stats['total'] += 1
        if TCP in pkt:
            self.traffic_stats['TCP'] += 1
        if UDP in pkt:
            self.traffic_stats['UDP'] += 1
        if ICMP in pkt:
            self.traffic_stats['ICMP'] += 1
        if ARP in pkt:
            self.traffic_stats['ARP'] += 1
        if pkt.haslayer(DNSQR):
            self.traffic_stats['DNS'] += 1

    def _update_rate_structs(self, src, length):
        now = time.time()
        dq = self.ip_rate[src]
        dq.append((now, length))
        cutoff = now - 60
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def process_packet(self, pkt):
        if not self.running:
            return

        info = {}
        alert = False
        info['time'] = datetime.utcnow().isoformat() + 'Z'

        if ARP in pkt:
            arp = pkt[ARP]
            info['type'] = 'ARP'
            info['src'] = arp.hwsrc
            info['dst'] = arp.hwdst
            info['proto'] = 'ARP'
            info['len'] = len(pkt)
            if arp.op == 1 and arp.psrc == arp.pdst:
                alert = True
                info['msg'] = f"[UYARI] ARP sahtekarlığı şüphesi: hwsrc={arp.hwsrc}"
                info['signature'] = 'arp_spoof'
            else:
                info['msg'] = f"ARP: {arp.psrc} -> {arp.pdst}"

        elif pkt.haslayer(DNSQR):
            dns = pkt[DNSQR]
            qname = dns.qname.decode(errors='ignore')
            info['type'] = 'DNS'
            info['src'] = pkt[IP].src if IP in pkt else ''
            info['dst'] = pkt[IP].dst if IP in pkt else ''
            info['proto'] = 'DNS'
            info['len'] = len(pkt)
            info['msg'] = f"DNS sorgusu: {qname}"
            if len(qname) > 100:
                alert = True
                info['signature'] = 'dns_long_query'
                info['msg'] += " [UYARI: uzun DNS sorgusu]"

        elif IP in pkt:
            ip = pkt[IP]
            src = ip.src
            dst = ip.dst
            info['src'] = src
            info['dst'] = dst
            info['len'] = ip.len
            info['proto'] = ip.proto

            self._mark_traffic(pkt)
            self._update_rate_structs(src, int(ip.len if hasattr(ip, 'len') else len(pkt)))

            if ICMP in pkt:
                ic = pkt[ICMP]
                t = ic.type
                info['type'] = 'ICMP'
                info['msg'] = f"ICMP type {t} {src} -> {dst}"

            elif TCP in pkt:
                tcp = pkt[TCP]
                sport = tcp.sport
                dport = tcp.dport
                flags = str(tcp.flags)
                info['type'] = 'TCP'
                info['sport'] = sport
                info['dport'] = dport
                info['flags'] = flags
                info['msg'] = f"TCP {src}:{sport} -> {dst}:{dport}, Flags={flags}, Len={ip.len}"

                if flags == 'S':
                    alert = True
                    info['signature'] = 'syn_scan'
                    info['msg'] = f"[UYARI] SYN tarama şüphesi {src}:{sport} -> {dst}:{dport}"
                    if dport == 22:
                        now = time.time()
                        dq = self.syn_counts[src]
                        dq.append(now)
                        cutoff = now - self.ssh_window_seconds
                        while dq and dq[0] < cutoff:
                            dq.popleft()
                        if len(dq) >= self.ssh_syn_threshold:
                            alert = True
                            info['signature'] = 'ssh_bruteforce'
                            info['msg'] = f"[KRİTİK] Olası SSH brute-force: {src} tarafından kısa sürede {len(dq)} SYN -> 22"

                if 'F' in flags and 'P' in flags and 'U' in flags:
                    alert = True
                    info['signature'] = 'xmas_scan'
                    info['msg'] = f"[UYARI] XMAS tarama {src} -> {dst}:{dport}"

                if flags in ('', '0'):
                    alert = True
                    info['signature'] = 'null_scan'
                    info['msg'] = f"[UYARI] NULL tarama: {src} -> {dst}:{dport}"

            elif UDP in pkt:
                udp = pkt[UDP]
                info['type'] = 'UDP'
                info['sport'] = udp.sport
                info['dport'] = udp.dport
                info['msg'] = f"UDP {src}:{udp.sport} -> {dst}:{udp.dport}, Len={ip.len}"

            else:
                info['type'] = 'IP'
                info['msg'] = f"IP {src} -> {dst}, proto={ip.proto}, Len={ip.len}"

            if self._is_rate_anomalous(src):
                alert = True
                prev = info.get('signature', '')
                info['signature'] = (prev + ';' if prev else '') + 'high_rate'
                info['msg'] = (info.get('msg', '') + ' [UYARI: yüksek trafik hızı]')

        else:
            info['type'] = 'OTHER'
            info['msg'] = 'Bilinmeyen paket tip'

        for rule in self.signature_rules:
            try:
                if rule['type'] == 'payload_regex' and pkt.haslayer('Raw'):
                    raw = bytes(pkt['Raw'].load)
                    if re.search(rule['pattern'].encode(), raw):
                        alert = True
                        info['signature'] = rule.get('name', 'payload_regex')
                        info['msg'] = info.get('msg', '') + f" [UYARI: imza {rule.get('name')}]"
            except Exception:
                pass

        info['alert'] = alert

        if self.alert_only and not alert:
            return

        self.packet_signal.emit(info)

    def _is_rate_anomalous(self, src):
        dq = self.ip_rate[src]
        now = time.time()
        cutoff = now - 60
        total_bytes = sum(b for (t, b) in dq if t >= cutoff)
        if total_bytes > 200 * 1024:
            return True
        return False


# ---------------------------
# Grafik bileşeni - iki grafik: zaman serisi ve pasta
# ---------------------------
class StatsCanvas(FigureCanvas):
    def __init__(self, parent=None):
        self.fig = Figure(figsize=(7, 3), tight_layout=True)
        super().__init__(self.fig)
        self.ax_time = self.fig.add_subplot(121)
        self.ax_pie = self.fig.add_subplot(122)

        self.times = []
        self.tcp_counts = []
        self.udp_counts = []
        self.icmp_counts = []
        self.total_counts = []

        self.setMinimumHeight(250)

    def update_stats(self, stats):
        now = datetime.now()
        self.times.append(now)
        self.tcp_counts.append(stats.get('TCP', 0))
        self.udp_counts.append(stats.get('UDP', 0))
        self.icmp_counts.append(stats.get('ICMP', 0))
        self.total_counts.append(stats.get('total', 0))

        # Sadece son 20 nokta
        if len(self.times) > 20:
            self.times.pop(0)
            self.tcp_counts.pop(0)
            self.udp_counts.pop(0)
            self.icmp_counts.pop(0)
            self.total_counts.pop(0)

        self.ax_time.clear()
        self.ax_pie.clear()

        self.ax_time.plot(self.times, self.tcp_counts, label='TCP', color='cyan')
        self.ax_time.plot(self.times, self.udp_counts, label='UDP', color='orange')
        self.ax_time.plot(self.times, self.icmp_counts, label='ICMP', color='magenta')
        self.ax_time.legend(loc='upper left')
        self.ax_time.set_title('Zaman serisi paket sayısı')
        self.ax_time.tick_params(axis='x', rotation=45)

        # Pasta grafik
        protocol_counts = {
            'TCP': stats.get('TCP', 0),
            'UDP': stats.get('UDP', 0),
            'ICMP': stats.get('ICMP', 0),
            'ARP': stats.get('ARP', 0),
            'DNS': stats.get('DNS', 0),
        }
        self.ax_pie.pie(protocol_counts.values(), labels=protocol_counts.keys(), autopct='%1.0f%%', startangle=140)
        self.ax_pie.set_title('Protokol Dağılımı')

        self.draw()


# ---------------------------
# Ana arayüz
# ---------------------------
class IDSApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IDS Uygulaması (PyQt5)")
        self.setGeometry(100, 100, 1100, 700)

        self.sniffer = None
        self.signature_rules = self.load_signatures()
        self.dark_theme = True

        self._init_ui()
        self._apply_theme()

    def _init_ui(self):
        layout = QVBoxLayout()

        # Arayüz başlığı
        lbl = QLabel("IDS - Ağ Trafik İzleme ve Anomali Tespiti")
        lbl.setFont(QFont("Arial", 14, QFont.Bold))
        lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(lbl)

        # Seçimler ve butonlar
        hl_top = QHBoxLayout()

        self.iface_combo = QComboBox()
        self.iface_combo.setToolTip("İzlenecek ağ arayüzünü seçin")
        self.iface_combo.addItems(self.get_interfaces())
        hl_top.addWidget(QLabel("Arayüz:"))
        hl_top.addWidget(self.iface_combo)

        self.alert_only_check = QCheckBox("Sadece Uyarılar Göster")
        hl_top.addWidget(self.alert_only_check)

        self.theme_btn = QPushButton("Tema: Koyu")
        self.theme_btn.clicked.connect(self.toggle_theme)
        hl_top.addWidget(self.theme_btn)

        self.start_btn = QPushButton("Başlat")
        self.start_btn.clicked.connect(self.start_sniffer)
        hl_top.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Durdur")
        self.stop_btn.clicked.connect(self.stop_sniffer)
        self.stop_btn.setEnabled(False)
        hl_top.addWidget(self.stop_btn)

        layout.addLayout(hl_top)

        # Tab widget - Paketler ve İstatistikler
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        # Paket tablosu
        self.table = QTableWidget()
        self.table.setColumnCount(9)
        self.table.setHorizontalHeaderLabels(["Zaman", "Tip", "Kaynak", "Kaynak Port", "Hedef", "Hedef Port", "Protokol", "Mesaj", "Uyarı"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        self.tabs.addTab(self.table, "Paketler")

        # Grafik tabı
        self.stats_canvas = StatsCanvas()
        self.tabs.addTab(self.stats_canvas, "İstatistikler")

        self.setLayout(layout)

    def get_interfaces(self):
        interfaces = psutil.net_if_addrs().keys()
        return sorted(interfaces)

    def load_signatures(self):
        # Burada imza kurallarını tanımlayabilirsin
        # Örnek: payload içinde belirli regexler
        return [
            {'name': 'bad_payload_example', 'type': 'payload_regex', 'pattern': 'maliciouspattern'}
        ]

    def toggle_theme(self):
        self.dark_theme = not self.dark_theme
        self._apply_theme()

    def _apply_theme(self):
        if self.dark_theme:
            self.setStyleSheet("""
                QWidget {
                    background-color: #2e2e2e;
                    color: #FFFFFF;
                }
                QTableWidget, QTableWidget QHeaderView::section {
                    background-color: #3e3e3e;
                    color: #FFFFFF;
                    gridline-color: #555555;
                }
                QTableWidget QTableCornerButton::section {
                    background-color: #3e3e3e;
                }
                QPushButton {
                    background-color: #005f5f;
                    color: white;
                    padding: 6px;
                    border-radius: 4px;
                }
                QPushButton:hover {
                    background-color: #008080;
                }
                QComboBox, QLineEdit {
                    background-color: #3e3e3e;
                    color: white;
                    border: 1px solid #555555;
                    padding: 2px 4px;
                    border-radius: 3px;
                }
                QCheckBox {
                    color: #CCCCCC;
                }
                QTabWidget::pane {
                    border: 1px solid #555555;
                    background: #3e3e3e;
                }
                QTabBar::tab {
                    background: #4e4e4e;
                    color: white;
                    padding: 6px;
                    border-top-left-radius: 4px;
                    border-top-right-radius: 4px;
                }
                QTabBar::tab:selected {
                    background: #007777;
                }
            """)
            btn_theme_text = "Tema: Koyu"
            self.stats_canvas.fig.patch.set_facecolor('#2e2e2e')
            self.stats_canvas.ax_time.set_facecolor('#3e3e3e')
            self.stats_canvas.ax_pie.set_facecolor('#3e3e3e')
            for ax in [self.stats_canvas.ax_time, self.stats_canvas.ax_pie]:
                ax.tick_params(colors='white', which='both')
                ax.xaxis.label.set_color('white')
                ax.yaxis.label.set_color('white')
                ax.title.set_color('white')
            self.stats_canvas.draw()
        else:
            self.setStyleSheet("""
                QWidget {
                    background-color: #f0f0f0;
                    color: black;
                }
                QTableWidget, QTableWidget QHeaderView::section {
                    background-color: white;
                    color: black;
                    gridline-color: #ccc;
                }
                QPushButton {
                    background-color: #0077cc;
                    color: white;
                    padding: 6px;
                    border-radius: 4px;
                }
                QPushButton:hover {
                    background-color: #005fa3;
                }
                QComboBox, QLineEdit {
                    background-color: white;
                    color: black;
                    border: 1px solid #ccc;
                    padding: 2px 4px;
                    border-radius: 3px;
                }
                QCheckBox {
                    color: black;
                }
                QTabWidget::pane {
                    border: 1px solid #ccc;
                    background: white;
                }
                QTabBar::tab {
                    background: #ddd;
                    color: black;
                    padding: 6px;
                    border-top-left-radius: 4px;
                    border-top-right-radius: 4px;
                }
                QTabBar::tab:selected {
                    background: #0077cc;
                    color: white;
                }
            """)
            btn_theme_text = "Tema: Açık"
            self.stats_canvas.fig.patch.set_facecolor('white')
            self.stats_canvas.ax_time.set_facecolor('white')
            self.stats_canvas.ax_pie.set_facecolor('white')
            for ax in [self.stats_canvas.ax_time, self.stats_canvas.ax_pie]:
                ax.tick_params(colors='black', which='both')
                ax.xaxis.label.set_color('black')
                ax.yaxis.label.set_color('black')
                ax.title.set_color('black')
            self.stats_canvas.draw()

        try:
            self.theme_btn.setText(btn_theme_text)
        except Exception:
            pass

    def start_sniffer(self):
        iface = self.iface_combo.currentText()
        alert_only = self.alert_only_check.isChecked()

        if self.sniffer and self.sniffer.isRunning():
            QMessageBox.warning(self, "Uyarı", "Zaten paket yakalama çalışıyor.")
            return

        self.sniffer = SnifferThread(iface, alert_only, self.signature_rules)
        self.sniffer.packet_signal.connect(self.add_packet)
        self.sniffer.stats_signal.connect(self.stats_canvas.update_stats)
        self.sniffer.start()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

    def stop_sniffer(self):
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None

        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def add_packet(self, pkt_info):
        row_pos = self.table.rowCount()
        self.table.insertRow(row_pos)

        def set_item(row, col, text, alert=False):
            item = QTableWidgetItem(str(text))
            if alert:
                item.setForeground(QBrush(QColor("red")))
                font = item.font()
                font.setBold(True)
                item.setFont(font)
            self.table.setItem(row, col, item)

        # Zaman, Tip, Kaynak, Kaynak Port, Hedef, Hedef Port, Protokol, Mesaj, Uyarı
        set_item(row_pos, 0, pkt_info.get('time', ''))
        set_item(row_pos, 1, pkt_info.get('type', ''))
        set_item(row_pos, 2, pkt_info.get('src', ''))
        set_item(row_pos, 3, pkt_info.get('sport', ''))
        set_item(row_pos, 4, pkt_info.get('dst', ''))
        set_item(row_pos, 5, pkt_info.get('dport', ''))
        set_item(row_pos, 6, pkt_info.get('proto', ''))
        set_item(row_pos, 7, pkt_info.get('msg', ''))
        set_item(row_pos, 8, "Evet" if pkt_info.get('alert', False) else "Hayır", alert=pkt_info.get('alert', False))

        # Yeni gelen paketin görünmesi için kaydır
        self.table.scrollToBottom()


def main():
    app = QApplication(sys.argv)
    window = IDSApp()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
