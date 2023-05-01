import socket
from concurrent.futures import ThreadPoolExecutor
import re
class PortScanner:
    def __init__(self, target_host, start_port, end_port, timeout=1):
        self.target_host = target_host
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout

    def scan(self):
        open_ports = []
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = []
            for port in range(self.start_port, self.end_port + 1):
                future = executor.submit(self.scan_port, port)
                futures.append(future)
            for future in futures:
                open_port = future.result()
                if open_port is not None:
                    open_ports.append(open_port)
        return open_ports

    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target_host, port))

            if result == 0:
                print(f"Port {port}: Open")
                return port

        except Exception as e:
            print(f"Error scanning port {port}: {e}")

        finally:
            sock.close()


if __name__ == "__main__":
    target_host = "www.hackthissite.org"
    start_port = 1
    end_port = 65535

    target_ip = socket.gethostbyname(target_host)
    scanner = PortScanner(target_ip, start_port, end_port)
    open_ports = scanner.scan()
    print(f"Open ports: {open_ports}")
    print(target_ip)
