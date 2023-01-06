import nmap
import sys
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout


class NmapScanner(QWidget):
    def __init__(self):
        super().__init__()

        # Create a label and a text box for the host
        self.host_label = QLabel("Enter host:")
        self.host_text_box = QLineEdit()

        # Create a label and a text box for the port range
        self.port_label = QLabel("Enter port range:")
        self.port_text_box = QLineEdit()

        # Create a scan button
        self.scan_button = QPushButton("Scan")
        self.scan_button.clicked.connect(self.scan)

        # Create a label to display the scan results
        self.results_label = QLabel("Scan results:")

        # Create a layout and add the widgets
        layout = QVBoxLayout()
        layout.addWidget(self.host_label)
        layout.addWidget(self.host_text_box)
        layout.addWidget(self.port_label)
        layout.addWidget(self.port_text_box)
        layout.addWidget(self.scan_button)
        layout.addWidget(self.results_label)
        self.setLayout(layout)

    def scan(self):
        # Get the host and port range from the text boxes
        host = self.host_text_box.text()
        port_range = self.port_text_box.text()

        # Create an instance of the nmap scanner
        nm = nmap.PortScanner()

        # Perform the scan
        nm.scan(host, port_range)

        # Display the results
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
