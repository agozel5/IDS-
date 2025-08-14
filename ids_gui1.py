import sys
import threading
import re
import requests
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNSQR
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QListWidget,
    QHBoxLayout, QFileDialog, QComboBox, QMessageBox, QCheckBox, QLineEdit
)
from PyQt5.QtCore import pyqtSignal, QThread
from PyQt5.QtGui import QFont, QIcon
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure


class SnifferThread(QThread):
    packet_signal = pyqtSignal(str)
    stats_signal = pyqtSignal(dict)

    def __init__(self, interface, alert_only):
        super().__init__()
        self.interface = interface
        self.alert_only = alert_only
        self.running = False
        self.traffic_stats = defaultdict(int)
        self.packet_buffer = []
        self.buffer_lock = threading.Lock()

    def run(self):
        from time import time
        self.running = True
        last_emit = time()
        while self.running:
            sniff(prn=self.process_packet, store=False, timeout=1, iface=self.interface)
            if time() - last_emit >= 0.5:
                with self.buffer_lock:
                    for log in self.packet_buffer:
                        self.packet_signal.emit(log)
                    self.packet_buffer.clear()
                self.stats_signal.emit(dict(self.traffic_stats))
                last_emit = time()

    def stop(self):
        self.running = False
        self.wait()

    def process_packet(self, pkt):
        log = ""
        alert = False

        if ARP in pkt:
            if pkt[ARP].op == 1 and pkt[ARP].psrc == pkt[ARP].pdst:
                alert = True
                log = f"[UYARI] ARP sahtekarlığı girişimi: {pkt[ARP].hwsrc}"

        elif pkt.haslayer(DNSQR):
            dns = pkt[DNSQR]
            log = f"[BİLGİ] DNS isteği: {dns.qname.decode()}"

        elif IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst

            if ICMP in pkt:
                icmp_type = pkt[ICMP].type
                if icmp_type == 8:
                    log = f"ICMP Echo İsteği (ping) {src} -> {dst}"
                elif icmp_type == 0:
                    log = f"ICMP Echo Yanıtı {src} -> {dst}"
                else:
                    log = f"ICMP tipi {icmp_type} {src} -> {dst}"

            elif TCP in pkt:
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                flags = pkt[TCP].flags
                log = f"TCP {src}:{sport} -> {dst}:{dport}, Bayraklar={flags}, Uzunluk={pkt[IP].len}"
                if flags == "S":
                    alert = True
                    log = f"[UYARI] SYN taraması {src}:{sport} -> {dst}:{dport}"

            elif UDP in pkt:
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                log = f"UDP {src}:{sport} -> {dst}:{dport}, Uzunluk={pkt[IP].len}"

            else:
                log = f"IP {src} -> {dst}, protokol={pkt[IP].proto}, Uzunluk={pkt[IP].len}"

        if log:
            if self.alert_only and not alert:
                return
            with self.buffer_lock:
                self.packet_buffer.append(log)

            self.traffic_stats['TCP'] += 1 if TCP in pkt else 0
            self.traffic_stats['UDP'] += 1 if UDP in pkt else 0
            self.traffic_stats['ICMP'] += 1 if ICMP in pkt else 0
            self.traffic_stats['ARP'] += 1 if ARP in pkt else 0
            self.traffic_stats['DNS'] += 1 if pkt.haslayer(DNSQR) else 0


class StatsCanvas(FigureCanvas):
    def __init__(self, parent=None):
        self.fig = Figure(figsize=(5, 2), tight_layout=True)
        self.ax = self.fig.add_subplot(111)
        super().__init__(self.fig)
        self.setParent(parent)

    def update_chart(self, stats):
        self.ax.clear()
        if stats:
            labels = list(stats.keys())
            values = list(stats.values())
            self.ax.bar(labels, values, color='cyan')
            self.ax.set_title("Trafik İstatistikleri")
            self.ax.set_ylabel("Paket Sayısı")
            self.ax.set_facecolor('#2e2e2e')
            self.fig.patch.set_facecolor('#2e2e2e')
            self.ax.tick_params(axis='x', colors='white')
            self.ax.tick_params(axis='y', colors='white')
            self.ax.title.set_color('white')
            self.ax.yaxis.label.set_color('white')
        self.draw()


class IDSApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IDS - Saldırı Tespit Sistemi")
        self.setGeometry(200, 100, 1100, 780)
        self.setStyleSheet("background-color: #2e2e2e; color: white;")
        self.setWindowIcon(QIcon.fromTheme("security"))

        self.log_entries = []

        title = QLabel("Kurumsal IDS - Gelişmiş ağ analizi")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setStyleSheet("color: #00FFFF;")

        self.log_list = QListWidget()
        self.log_list.setStyleSheet("background-color: #1e1e1e; color: white;")
        self.log_list.itemDoubleClicked.connect(self.show_ip_details)

        import psutil
        self.interface_select = QComboBox()
        self.interface_select.setStyleSheet("background-color: #444; color: white;")
        self.iface_map = {}

        for iface, addrs in psutil.net_if_addrs().items():
            ip = None
            for addr in addrs:
                if addr.family.name == 'AF_INET':
                    ip = addr.address
                    break
            label = f"{iface} ({ip})" if ip else f"{iface} (IP yok)"
            self.iface_map[label] = iface
            self.interface_select.addItem(label)

        self.start_btn = QPushButton("Başlat")
        self.stop_btn = QPushButton("Durdur")
        self.export_btn = QPushButton("Logları Dışa Aktar")
        for btn in [self.start_btn, self.stop_btn, self.export_btn]:
            btn.setStyleSheet("background-color: #005f5f; color: white; padding: 6px;")

        self.stop_btn.setEnabled(False)
        self.alert_only_checkbox = QCheckBox("Sadece uyarıları göster")
        self.alert_only_checkbox.setStyleSheet("color: #CCCCCC")
        self.alert_only_checkbox.stateChanged.connect(self.update_alert_only)

        self.filter_tcp = QCheckBox("TCP")
        self.filter_udp = QCheckBox("UDP")
        self.filter_icmp = QCheckBox("ICMP")
        self.filter_arp = QCheckBox("ARP")
        self.filter_dns = QCheckBox("DNS")
        self.filter_alert = QCheckBox("Uyarılar")

        for cb in [self.filter_tcp, self.filter_udp, self.filter_icmp, self.filter_arp, self.filter_dns, self.filter_alert]:
            cb.setChecked(True)
            cb.setStyleSheet("color: #CCCCCC")
            cb.stateChanged.connect(self.apply_filters)

        self.ip_src_filter = QLineEdit()
        self.ip_src_filter.setPlaceholderText("Kaynak IP filtrele")
        self.ip_src_filter.setStyleSheet("background-color: #444; color: white;")
        self.ip_src_filter.textChanged.connect(self.apply_filters)

        self.ip_dst_filter = QLineEdit()
        self.ip_dst_filter.setPlaceholderText("Hedef IP filtrele")
        self.ip_dst_filter.setStyleSheet("background-color: #444; color: white;")
        self.ip_dst_filter.textChanged.connect(self.apply_filters)

        self.stats_chart = StatsCanvas(self)

        btn_layout = QHBoxLayout()
        btn_layout.addWidget(self.interface_select)
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        btn_layout.addWidget(self.export_btn)
        btn_layout.addWidget(self.alert_only_checkbox)

        filter_layout = QHBoxLayout()
        for cb in [self.filter_tcp, self.filter_udp, self.filter_icmp, self.filter_arp, self.filter_dns, self.filter_alert]:
            filter_layout.addWidget(cb)
        filter_layout.addWidget(self.ip_src_filter)
        filter_layout.addWidget(self.ip_dst_filter)

        layout = QVBoxLayout()
        layout.addWidget(title)
        layout.addLayout(btn_layout)
        layout.addLayout(filter_layout)
        layout.addWidget(self.log_list)
        layout.addWidget(self.stats_chart)

        self.setLayout(layout)

        self.sniffer_thread = None
        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn.clicked.connect(self.stop_capture)
        self.export_btn.clicked.connect(self.export_logs)

        self.current_filters = {
            'tcp': True,
            'udp': True,
            'icmp': True,
            'arp': True,
            'dns': True,
            'alert': True,
            'ip_src': '',
            'ip_dst': '',
        }

    def start_capture(self):
        iface_label = self.interface_select.currentText()
        iface = self.iface_map.get(iface_label)
        if not iface:
            QMessageBox.warning(self, "Hata", "Ağ arayüzü seçilmedi")
            return
        alert_only = self.alert_only_checkbox.isChecked()

        self.sniffer_thread = SnifferThread(iface, alert_only)
        self.sniffer_thread.packet_signal.connect(self.add_log_entry)
        self.sniffer_thread.stats_signal.connect(self.stats_chart.update_chart)
        self.sniffer_thread.start()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

    def stop_capture(self):
        if self.sniffer_thread and self.sniffer_thread.isRunning():
            self.sniffer_thread.stop()
            self.sniffer_thread = None
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def export_logs(self):
        path, _ = QFileDialog.getSaveFileName(self, "Logları dışa aktar", "", "Metin Dosyaları (*.txt)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                for entry in self.log_entries:
                    f.write(entry + "\n")
            QMessageBox.information(self, "Dışa Aktarma", f"Loglar {path} konumuna kaydedildi")

    def update_alert_only(self, state):
        QMessageBox.information(self, "Bilgi", "'Sadece uyarılar' filtresi bir sonraki yakalama başlatıldığında uygulanacaktır.")

    def add_log_entry(self, entry):
        self.log_entries.append(entry)
        if self.passes_filter(entry):
            self.log_list.addItem(entry)

    def passes_filter(self, entry):
        f = self.current_filters
        entry_low = entry.lower()

        if f['ip_src'] and f['ip_src'] not in entry:
            return False
        if f['ip_dst'] and f['ip_dst'] not in entry:
            return False

        if "[uyarı]" in entry_low and not f['alert']:
            return False
        if entry.startswith("TCP") and not f['tcp']:
            return False
        if entry.startswith("UDP") and not f['udp']:
            return False
        if entry.startswith("ICMP") and not f['icmp']:
            return False
        if entry.startswith("[UYARI] ARP sahtekarlığı girişimi") and not f['arp']:
            return False
        if entry.startswith("[BİLGİ] DNS isteği") and not f['dns']:
            return False

        return True

    def apply_filters(self):
        self.current_filters['tcp'] = self.filter_tcp.isChecked()
        self.current_filters['udp'] = self.filter_udp.isChecked()
        self.current_filters['icmp'] = self.filter_icmp.isChecked()
        self.current_filters['arp'] = self.filter_arp.isChecked()
        self.current_filters['dns'] = self.filter_dns.isChecked()
        self.current_filters['alert'] = self.filter_alert.isChecked()
        self.current_filters['ip_src'] = self.ip_src_filter.text().strip()
        self.current_filters['ip_dst'] = self.ip_dst_filter.text().strip()

        self.log_list.clear()
        for entry in self.log_entries:
            if self.passes_filter(entry):
                self.log_list.addItem(entry)

    def show_ip_details(self, item):
        text = item.text()
        ip_matches = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)

        if not ip_matches:
            QMessageBox.information(self, "Bilgi", "Bu logda IP adresi bulunamadı.")
            return

        ip = ip_matches[0]

        try:
            resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,query", timeout=5)
            data = resp.json()

            if data['status'] != 'success':
                raise Exception(data.get('message', 'Bilinmeyen hata'))

            info = f"""
<b>IP Adresi :</b> {data['query']}
<b>Ülke :</b> {data['country']}
<b>Bölge :</b> {data['regionName']}
<b>Şehir :</b> {data['city']}
<b>ISS :</b> {data['isp']}
<b>Organizasyon :</b> {data['org']}
<b>ASN :</b> {data['as']}
            """.strip()

            QMessageBox.information(self, "IP Detayları", info)

        except Exception as e:
            QMessageBox.warning(self, "Hata", f"{ip} IP'si için bilgi alınamadı.\n{str(e)}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = IDSApp()
    window.show()
    sys.exit(app.exec_())
