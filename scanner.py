import nmap
import sys
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout


class NmapScanner(QWidget):
    def __init__(self):
        super().__init__()


        self.host_label = QLabel("Enter host:")
        self.host_text_box = QLineEdit()

        self.port_label = QLabel("Enter port range:")
        self.port_text_box = QLineEdit()


        self.scan_button = QPushButton("Scan")
        self.scan_button.clicked.connect(self.scan)


        self.results_label = QLabel("Scan results:")


        layout = QVBoxLayout()
        layout.addWidget(self.host_label)
        layout.addWidget(self.host_text_box)
        layout.addWidget(self.port_label)
        layout.addWidget(self.port_text_box)
        layout.addWidget(self.scan_button)
        layout.addWidget(self.results_label)
        self.setLayout(layout)

    def scan(self):

        host = self.host_text_box.text()
        port_range = self.port_text_box.text()


        nm = nmap.PortScanner()

   
        nm.scan(host, port_range)


        results = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    results.append(f"Port {port}: {nm[host][proto][port]['state']}")
        self.results_label.setText("\n".join(results))


if __name__ == "__main__":
    app = QApplication(sys.argv)
    scanner = NmapScanner()
    scanner.show()
    sys.exit(app.exec_())
