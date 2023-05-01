import socket
import threading
import argparse
from typing import *

class PortScanner:
    def __init__(self, target, start_port, end_port):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.open_ports = []

    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                self.open_ports.append(port)
            sock.close()
        except:
            pass

    def scan_range(self):
        for port in range(self.start_port, self.end_port+1):
            thread = threading.Thread(target=self.scan_port, args=(port,))
            thread.start()

    def run(self):
        self.scan_range()
        threading.active_count() # Wait for all threads to finish
        return self.open_ports


scanner = PortScanner('127.0.0.1', 1, 1024)
open_ports = scanner.run()
print(open_ports)
