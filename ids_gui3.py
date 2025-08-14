# ids_optimized.py
"""
Version optimisée du IDS pour réduire les freezes :
- SnifferThread: capture -> push vers queue
- ProcessorThread: pop de la queue, analyse, accumulate batch -> émet batch_signal(list[info])
- UI: reçoit batch et met à jour le QTableWidget en une seule fois
- Limite sur le nombre de lignes du tableau
- Regex précompilées, structures légères
"""

import sys
import threading
import re
from collections import defaultdict, deque
from datetime import datetime
import time
from queue import Queue, Empty

import psutil
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNSQR

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QTableWidget,
    QTableWidgetItem, QHBoxLayout, QFileDialog, QComboBox, QMessageBox, QCheckBox,
    QLineEdit, QHeaderView, QAbstractItemView, QTabWidget, QSizePolicy
)
from PyQt5.QtCore import pyqtSignal, QThread, Qt, QTimer
from PyQt5.QtGui import QFont, QColor, QBrush

from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

# ---------------------------
# Configs
# ---------------------------
MAX_TABLE_ROWS = 2000            # max lignes dans la table (eviter mémoire infinie)
BATCH_INTERVAL = 0.5             # secondes : intervalle d'émission des batches depuis ProcessorThread
QUEUE_MAXSIZE = 20000            # taille max de la queue pour backpressure (ajuster selon besoin)

# ---------------------------
# SnifferThread : capture rapide, push raw pkt dans queue
# ---------------------------
class SnifferThread(QThread):
    # émets un simple signal pour informer stats régulières (optionnel)
    raw_pkt_put = pyqtSignal(int)  # count put since last emit (utile debug)

    def __init__(self, interface, raw_queue):
        super().__init__()
        self.interface = interface
        self.raw_queue = raw_queue
        self.running = False
        self._put_count = 0

    def run(self):
        self.running = True
        while self.running:
            try:
                # sniff timeout 1s -> retourne régulièrement le contrôle
                sniff(prn=self._on_pkt, store=False, timeout=1, iface=self.interface)
            except Exception as e:
                # ne pas mourir sur erreur de sniff
                print("sniff error:", e)
            # possibilité d'émettre un petit compteur (debug)
            if self._put_count:
                self.raw_pkt_put.emit(self._put_count)
                self._put_count = 0

    def _on_pkt(self, pkt):
        # essayer d'insérer sans blocage important
        try:
            self.raw_queue.put_nowait(pkt)
            self._put_count += 1
        except Exception:
            # queue pleine -> drop packet (préfère drop que freeze)
            pass

    def stop(self):
        self.running = False
        self.wait()


# ---------------------------
# ProcessorThread : consomme queue, analyse, envoie des batches vers UI
# ---------------------------
class ProcessorThread(QThread):
    batch_signal = pyqtSignal(list)   # liste d'info dict à envoyer à l'UI
    stats_signal = pyqtSignal(dict)   # statistiques agrégées

    def __init__(self, raw_queue, signature_rules=None, alert_only=False):
        super().__init__()
        self.raw_queue = raw_queue
        self.signature_rules = signature_rules or []
        self.running = False
        self.alert_only = alert_only

        # structures légères pour les détections
        self.traffic_stats = defaultdict(int)
        self.syn_counts = defaultdict(deque)   # src -> deque(timestamps)
        self.ip_packet_times = defaultdict(deque)  # src -> deque(timestamps)
        # précompiler patterns
        self.compiled_rules = []
        for r in self.signature_rules:
            if r.get('type') == 'payload_regex':
                try:
                    self.compiled_rules.append((r.get('name'), re.compile(r.get('pattern').encode())))
                except Exception:
                    # essayer pattern text (fallback)
                    try:
                        self.compiled_rules.append((r.get('name'), re.compile(r.get('pattern'))))
                    except Exception:
                        pass

        # polling params
        self.batch_interval = BATCH_INTERVAL
        self._last_stats_emit = time.time()

    def run(self):
        self.running = True
        batch = []
        next_emit = time.time() + self.batch_interval
        while self.running:
            now = time.time()
            time_left = max(0.0, next_emit - now)
            try:
                # get one packet with timeout small to allow periodic emits
                pkt = self.raw_queue.get(timeout=time_left)
                info = self._process_raw_pkt(pkt)
                # si alert_only et pas d'alerte -> on peut l'ignorer
                if not (self.alert_only and not info.get('alert', False)):
                    batch.append(info)
                # continue to try draining quickly (but don't starve emit)
                # drain a few more quickly
                for _ in range(50):
                    try:
                        pkt = self.raw_queue.get_nowait()
                        info = self._process_raw_pkt(pkt)
                        if not (self.alert_only and not info.get('alert', False)):
                            batch.append(info)
                    except Empty:
                        break
            except Empty:
                # délai expiré -> il est temps d'émettre batch si vide ou non
                pass

            if time.time() >= next_emit:
                if batch:
                    # émettre batch (liste d'infos) à l'UI en une fois
                    try:
                        self.batch_signal.emit(batch.copy())
                    except Exception:
                        pass
                    batch.clear()
                # envoyer stats périodiques (utile UI graphique)
                try:
                    self.stats_signal.emit(dict(self.traffic_stats))
                except Exception:
                    pass
                next_emit = time.time() + self.batch_interval

    def stop(self):
        self.running = False
        self.wait()

    # ---------------------------
    # méthode d'analyse (optimisée, légère)
    # ---------------------------
    def _process_raw_pkt(self, pkt):
        info = {}
        alert = False
        reasons = []

        info['time'] = datetime.utcnow().isoformat() + 'Z'

        try:
            if ARP in pkt:
                arp = pkt[ARP]
                info['type'] = 'ARP'
                info['src'] = arp.hwsrc
                info['dst'] = arp.hwdst
                info['proto'] = 'ARP'
                info['len'] = len(pkt)
                if getattr(arp, 'op', None) == 1 and getattr(arp, 'psrc', None) == getattr(arp, 'pdst', None):
                    alert = True
                    reasons.append('arp_spoof')
                    info['msg'] = f"[UYARI] ARP sahtekarlığı şüphesi: hwsrc={arp.hwsrc}"
                else:
                    info['msg'] = f"ARP: {getattr(arp,'psrc','')} -> {getattr(arp,'pdst','')}"
            elif pkt.haslayer(DNSQR):
                dns = pkt[DNSQR]
                try:
                    qname = dns.qname.decode(errors='ignore')
                except Exception:
                    qname = str(getattr(dns,'qname',''))
                info['type'] = 'DNS'
                info['src'] = pkt[IP].src if IP in pkt else ''
                info['dst'] = pkt[IP].dst if IP in pkt else ''
                info['proto'] = 'DNS'
                info['len'] = len(pkt)
                info['msg'] = f"DNS sorgusu: {qname}"
                if len(qname) > 100:
                    alert = True
                    reasons.append('dns_long_query')
                    info['signature'] = 'dns_long_query'
                    info['msg'] += " [UYARI: uzun DNS sorgusu]"
            elif IP in pkt:
                ip = pkt[IP]
                src = ip.src
                dst = ip.dst
                info['src'] = src
                info['dst'] = dst
                info['len'] = getattr(ip, 'len', len(pkt))
                info['proto'] = getattr(ip, 'proto', '')
                # update light stats
                self.traffic_stats['total'] += 1
                if TCP in pkt:
                    self.traffic_stats['TCP'] += 1
                if UDP in pkt:
                    self.traffic_stats['UDP'] += 1
                if ICMP in pkt:
                    self.traffic_stats['ICMP'] += 1
                if pkt.haslayer(DNSQR):
                    self.traffic_stats['DNS'] += 1
                if ARP in pkt:
                    self.traffic_stats['ARP'] += 1

                # maintain simple per-src packet timestamps for basic rate detection
                now_ts = time.time()
                dq = self.ip_packet_times[src]
                dq.append(now_ts)
                # keep only last 60s timestamps
                cutoff = now_ts - 60
                while dq and dq[0] < cutoff:
                    dq.popleft()

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
                    info['msg'] = f"TCP {src}:{sport} -> {dst}:{dport}, Flags={flags}, Len={info['len']}"

                    # SYN initial
                    if 'S' in flags and 'A' not in flags:
                        syndq = self.syn_counts[src]
                        syndq.append(now_ts)
                        # keep within window 20s
                        cutoff2 = now_ts - 20
                        while syndq and syndq[0] < cutoff2:
                            syndq.popleft()
                        if len(syndq) >= 20:
                            alert = True
                            reasons.append('ssh_bruteforce_or_syn_flood')
                            info['signature'] = 'syn_flood_or_bruteforce'
                            info['msg'] = f"[KRITİK] Çok SYN: {len(syndq)} from {src} -> {dst}:{dport}"
                    # XMAS / NULL heuristics
                    if 'F' in flags and 'P' in flags and 'U' in flags:
                        alert = True
                        reasons.append('xmas_scan')
                    if flags in ('', '0'):
                        alert = True
                        reasons.append('null_scan')
                elif UDP in pkt:
                    udp = pkt[UDP]
                    info['type'] = 'UDP'
                    info['sport'] = udp.sport
                    info['dport'] = udp.dport
                    info['msg'] = f"UDP {src}:{udp.sport} -> {dst}:{udp.dport}, Len={info['len']}"
                else:
                    info['type'] = 'IP'
                    info['msg'] = f"IP {src} -> {dst}, proto={info['proto']}, Len={info['len']}"

                # rate anomaly: total bytes in last 60s approximated by packet count
                if len(self.ip_packet_times[src]) > 500:  # simple heuristic
                    alert = True
                    reasons.append('high_rate')
                    info['msg'] = info.get('msg','') + ' [UYARI: yüksek trafik (pkt count)]'
            else:
                info['type'] = 'OTHER'
                info['msg'] = 'Bilinmeyen paket tip'
        except Exception as e:
            # si l'analyse plante, on renvoie un mini résumé pour debug
            info['type'] = 'PARSE_ERROR'
            info['msg'] = f'parse error: {e}'
            alert = False

        # signature_rules check (utiliser compiled_rules, très léger)
        try:
            if self.compiled_rules and pkt.haslayer('Raw'):
                raw_bytes = bytes(pkt['Raw'].load)
                for name, cre in self.compiled_rules:
                    try:
                        if cre.search(raw_bytes):
                            alert = True
                            reasons.append(name or 'payload_regex')
                            info['msg'] = info.get('msg','') + f" [IMZA: {name}]"
                            info['signature'] = name
                    except Exception:
                        continue
        except Exception:
            pass

        info['alert'] = alert
        info['reasons'] = reasons
        return info


# ---------------------------
# UI Application : reçoit batch et met à jour table en bloc
# ---------------------------
class IDSApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IDS Optimized - Reduced Freezes")
        self.setGeometry(120, 60, 1200, 800)

        # queue partagée
        self.raw_queue = Queue(maxsize=QUEUE_MAXSIZE)

        # threads
        self.sniffer_thread = None
        self.processor_thread = None

        # signatures example (tu peux ajouter)
        self.signature_rules = [
            {'name': 'bad_agent', 'type': 'payload_regex', 'pattern': 'malicious_agent'}
        ]

        # logs limitées (pour UI et export)
        self.log_entries = deque(maxlen=50000)

        self._init_ui()
        # connect batch handler
        # démarrage manuel via bouton

    def _init_ui(self):
        self.layout = QVBoxLayout()

        title = QLabel("IDS - Optimized (no freeze)")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(title)

        # controls
        ctrl_layout = QHBoxLayout()
        self.iface_combo = QComboBox()
        # peupler interfaces
        for iface, addrs in psutil.net_if_addrs().items():
            ip = None
            for a in addrs:
                if getattr(a, 'family', None) and str(getattr(a, 'family')).find('AF_INET') != -1:
                    ip = getattr(a, 'address', None)
                    break
            label = f"{iface} ({ip})" if ip else f"{iface} (no IP)"
            self.iface_combo.addItem(label, iface)
        ctrl_layout.addWidget(self.iface_combo)

        self.start_btn = QPushButton("Démarrer")
        self.start_btn.clicked.connect(self.start_capture)
        ctrl_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Arrêter")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_capture)
        ctrl_layout.addWidget(self.stop_btn)

        self.alert_only_cb = QCheckBox("Afficher seulement les alertes")
        ctrl_layout.addWidget(self.alert_only_cb)

        # bouton vidage table
        clear_btn = QPushButton("Vider table")
        clear_btn.clicked.connect(self.clear_table)
        ctrl_layout.addWidget(clear_btn)

        self.layout.addLayout(ctrl_layout)

        # filtre simple
        filter_layout = QHBoxLayout()
        self.filter_src = QLineEdit(); self.filter_src.setPlaceholderText("Filtre source IP")
        self.filter_dst = QLineEdit(); self.filter_dst.setPlaceholderText("Filtre dest IP")
        self.search_text = QLineEdit(); self.search_text.setPlaceholderText("Recherche dans msg")
        self.filter_src.textChanged.connect(self.apply_filters_ui)  # réappliquer sur changements
        self.filter_dst.textChanged.connect(self.apply_filters_ui)
        self.search_text.textChanged.connect(self.apply_filters_ui)
        filter_layout.addWidget(self.filter_src)
        filter_layout.addWidget(self.filter_dst)
        filter_layout.addWidget(self.search_text)
        self.layout.addLayout(filter_layout)

        # table
        self.table = QTableWidget(0, 9)
        self.table.setHorizontalHeaderLabels([
            "Heure", "Type", "Src", "SrcPort", "Dst", "DstPort", "Proto", "Len", "Msg/Alert"
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSortingEnabled(False)
        self.table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.layout.addWidget(self.table)

        # stats graph minimal (non-blocking)
        self.stats_canvas = SimpleStatsCanvas()
        self.layout.addWidget(self.stats_canvas)

        self.setLayout(self.layout)

    # start / stop threads
    def start_capture(self):
        iface = self.iface_combo.currentData()
        if not iface:
            QMessageBox.warning(self, "Erreur", "Sélectionne une interface")
            return
        # créer et démarrer sniffer thread
        self.sniffer_thread = SnifferThread(interface=iface, raw_queue=self.raw_queue)
        self.sniffer_thread.start()

        # processor thread (analyse + batch)
        self.processor_thread = ProcessorThread(raw_queue=self.raw_queue,
                                                signature_rules=self.signature_rules,
                                                alert_only=self.alert_only_cb.isChecked())
        self.processor_thread.batch_signal.connect(self.add_packet_batch)
        self.processor_thread.stats_signal.connect(self.stats_canvas.update_stats)
        self.processor_thread.start()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

    def stop_capture(self):
        if self.sniffer_thread:
            self.sniffer_thread.stop()
            self.sniffer_thread = None
        if self.processor_thread:
            self.processor_thread.stop()
            self.processor_thread = None
        # vider la queue pour repartir propre
        with self.raw_queue.mutex:
            self.raw_queue.queue.clear()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    # table management : add batch atomically
    def add_packet_batch(self, infos):
        """
        Ajoute un lot (list) d'entrées à la table en opérant des filtres et en limitant le nombre de lignes.
        """
        # appliquer filtre UI (si présent), filtrer le batch avant insertion
        src_filter = self.filter_src.text().strip()
        dst_filter = self.filter_dst.text().strip()
        text_filter = self.search_text.text().strip().lower()

        to_add = []
        for info in infos:
            if src_filter and src_filter not in (info.get('src') or ""):
                continue
            if dst_filter and dst_filter not in (info.get('dst') or ""):
                continue
            if text_filter:
                hay = (info.get('msg','') + ' ' + ' '.join(info.get('reasons',[]))).lower()
                if text_filter not in hay:
                    continue
            to_add.append(info)
            # garder log global limité
            self.log_entries.append(info)

        if not to_add:
            return

        # insertion en bloc: on ajoute lignes puis on remplit items (évite repaint multiple)
        current_rows = self.table.rowCount()
        self.table.setRowCount(current_rows + len(to_add))
        for i, info in enumerate(to_add, start=current_rows):
            self._set_row(i, info)

        # réduire nombre de lignes si > MAX_TABLE_ROWS
        if self.table.rowCount() > MAX_TABLE_ROWS:
            # supprime les premières lignes (ancienne)
            rows_to_remove = self.table.rowCount() - MAX_TABLE_ROWS
            # décalage : on supprime répétitivement la première ligne
            for _ in range(rows_to_remove):
                self.table.removeRow(0)

        # ensure visible latest
        self.table.scrollToBottom()

    def _set_row(self, row, info):
        def make_item(text, alert=False):
            it = QTableWidgetItem(str(text))
            if alert:
                it.setForeground(QBrush(QColor("red")))
                f = it.font(); f.setBold(True); it.setFont(f)
            return it
        self.table.setItem(row, 0, make_item(info.get('time','')))
        self.table.setItem(row, 1, make_item(info.get('type','')))
        self.table.setItem(row, 2, make_item(info.get('src','')))
        self.table.setItem(row, 3, make_item(info.get('sport','')))
        self.table.setItem(row, 4, make_item(info.get('dst','')))
        self.table.setItem(row, 5, make_item(info.get('dport','')))
        self.table.setItem(row, 6, make_item(info.get('proto','')))
        self.table.setItem(row, 7, make_item(info.get('len','')))
        msg = info.get('msg','')
        if info.get('alert'):
            msg = "🚨 " + msg + " | " + ','.join(info.get('reasons',[]))
        self.table.setItem(row, 8, make_item(msg, alert=info.get('alert', False)))

    def clear_table(self):
        self.table.setRowCount(0)
        self.log_entries.clear()

    def apply_filters_ui(self):
        """Si tu veux réappliquer un filtre à tout le log (coûteux) - on évite souvent."""
        # ici on réaffiche seulement les dernières N logs (pour éviter freeze)
        # implémentation simple : vider la table et réinsérer un sous-ensemble récent
        filtered = []
        src_filter = self.filter_src.text().strip()
        dst_filter = self.filter_dst.text().strip()
        text_filter = self.search_text.text().strip().lower()
        # on prend au plus 5000 derniers logs pour ne pas freeze
        sample = list(self.log_entries)[-5000:]
        for info in sample:
            if src_filter and src_filter not in (info.get('src') or ""):
                continue
            if dst_filter and dst_filter not in (info.get('dst') or ""):
                continue
            if text_filter:
                hay = (info.get('msg','') + ' ' + ' '.join(info.get('reasons',[]))).lower()
                if text_filter not in hay:
                    continue
            filtered.append(info)

        # refresh table (attention performance)
        self.table.setRowCount(0)
        self.table.setRowCount(len(filtered))
        for idx, info in enumerate(filtered):
            self._set_row(idx, info)

# ---------------------------
# SimpleStatsCanvas : très léger, non bloquant
# ---------------------------
class SimpleStatsCanvas(FigureCanvas):
    def __init__(self, parent=None):
        self.fig = Figure(figsize=(8, 2), tight_layout=True)
        super().__init__(self.fig)
        self.ax_time = self.fig.add_subplot(121)
        self.ax_pie = self.fig.add_subplot(122)
        self.times = deque(maxlen=40)
        self.totals = deque(maxlen=40)

    def update_stats(self, stats):
        try:
            self.times.append(datetime.now().strftime("%H:%M:%S"))
            self.totals.append(stats.get('total', 0))
            self.ax_time.clear()
            self.ax_pie.clear()
            if self.times:
                self.ax_time.plot(list(range(len(self.totals))), list(self.totals))
                self.ax_time.set_title("Pkts samples")
            proto_keys = ['TCP','UDP','ICMP','ARP','DNS']
            vals = [stats.get(k,0) for k in proto_keys]
            if sum(vals) > 0:
                self.ax_pie.pie(vals, labels=proto_keys, autopct='%1.0f%%')
            else:
                self.ax_pie.text(0.5,0.5,"No data", ha='center')
            self.draw()
        except Exception:
            pass

# ---------------------------
# main
# ---------------------------
def main():
    app = QApplication(sys.argv)
    window = IDSApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
