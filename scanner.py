import socket
from concurrent.futures import ThreadPoolExecutor
import re
import argparse
class PortScanner:
    def __init__(self, target_host, start_port, end_port, timeout=1):
        self.__target_host = target_host
        self.__start_port = start_port
        self.__end_port = end_port
        self.__timeout = timeout

    def scan(self):
        open_ports = []
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = []
            for port in range(self.__start_port, self.__end_port + 1):
                future = executor.submit(self.__scan_port, port)
                futures.append(future)
            for future in futures:
                open_port = future.result()
                if open_port is not None:
                    open_ports.append(open_port)
        return open_ports

    def __scan_port(self, port):
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

def valid_port(value):
    ivalue = int(value)
    if ivalue < 1 or ivalue > 65535:
         raise argparse.ArgumentTypeError(f"Invalid port number: {value}")
    return ivalue

def parse_args():
    parser = argparse.ArgumentParser(description="Port scanner")
    parser.add_argument("host", help="Host to scan")
    parser.add_argument("start_port", help="Start port", type=valid_port, metavar="Start_Port[1-65535]")
    parser.add_argument("end_port", help="End port", type=valid_port, metavar="End_Port[1-65535]")
    parser.add_argument("--timeout", help="Timeout (seconds)", type=int, default=1)
    parser.add_argument("-t","--threads", help="Number of threads", type=int, default=1)
    return parser.parse_args()

if __name__ == "__main__":
    target_host = "www.hackthissite.org"
    start_port = 1
    end_port = 65535

    target_ip = socket.gethostbyname(target_host)
    scanner = PortScanner(target_ip, start_port, end_port)
    open_ports = scanner.scan()
    print(f"Open ports: {open_ports}")
    print(target_ip)
