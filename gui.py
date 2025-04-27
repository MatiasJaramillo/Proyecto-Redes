# packet_gui_qt.py
import sys, requests
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QListWidget, QLabel
)
from PySide6.QtCore import QTimer

SNIFFER_URL = "http://192.168.1.10:5000"
SENDER_URL  = "http://192.168.1.10:5001"

class PacketGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Packet Sniffer & Sender")
        self.resize(800, 600)

        # Track seen suspicious packets to avoid duplicates
        self.seen_susp = set()

        # Top row of buttons
        top_layout = QHBoxLayout()
        for label, fn in [
            ("Start Sniffing", self.start_sniff),
            ("Stop Sniffing",  self.stop_sniff),
            ("FPU Scan",       lambda: self.send_scan("fpu")),
            ("Null Scan",      lambda: self.send_scan("null")),
        ]:
            btn = QPushButton(label)
            btn.clicked.connect(fn)
            top_layout.addWidget(btn)

        # Two list widgets side by side
        lists_layout = QHBoxLayout()
        self.all_list  = QListWidget()
        self.susp_list = QListWidget()
        self.susp_list.setStyleSheet("color: red;")
        lists_layout.addWidget(self._with_label("All Packets",  self.all_list))
        lists_layout.addWidget(self._with_label("Suspicious Packets", self.susp_list))

        # Put it all together
        main_layout = QVBoxLayout(self)
        main_layout.addLayout(top_layout)
        main_layout.addLayout(lists_layout)

        # Polling timer (1 s)
        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.poll_logs)

    def _with_label(self, text, widget):
        """Helper to put a label above a widget."""
        container = QVBoxLayout()
        container.addWidget(QLabel(text))
        container.addWidget(widget)
        w = QWidget()
        w.setLayout(container)
        return w

    def start_sniff(self):
        try:
            requests.post(f"{SNIFFER_URL}/start_sniff", timeout=2).raise_for_status()
            self.timer.start()
        except Exception as e:
            print("Error starting sniff:", e)

    def stop_sniff(self):
        try:
            requests.post(f"{SNIFFER_URL}/stop_sniff", timeout=2).raise_for_status()
            self.timer.stop()
        except Exception as e:
            print("Error stopping sniff:", e)

    def send_scan(self, scan_type):
        try:
            r = requests.post(f"{SENDER_URL}/send_{scan_type}", timeout=2)
            r.raise_for_status()
            print("Sent", scan_type, "scan:", r.json().get("sent"))
        except Exception as e:
            print("Error sending scan:", e)

    def poll_logs(self):
        try:
            r = requests.get(f"{SNIFFER_URL}/logs", timeout=2)
            r.raise_for_status()
            logs = r.json()

            # Refresh only the All Packets list
            self.all_list.clear()
            for e in logs:
                summary = e.get("summary", "")
                self.all_list.addItem(summary)

                # Append new suspicious packets without clearing
                if e.get("suspicious") and summary not in self.seen_susp:
                    self.seen_susp.add(summary)
                    self.susp_list.addItem(summary)
        except Exception as e:
            print("Polling error:", e)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    gui = PacketGUI()
    gui.show()
    sys.exit(app.exec())
