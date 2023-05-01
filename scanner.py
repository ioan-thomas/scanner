import socket
from concurrent.futures import ThreadPoolExecutor
import re
import argparse

class PortScanner:
    def __init__(self, args):
        self.__target_host = args.host
        self.__start_port = args.start_port
        self.__end_port = args.end_port
        self.__timeout = args.timeout
        self.__max_workers = args.threads

    def scan(self):
        open_ports = []
        with ThreadPoolExecutor(max_workers=self.__max_workers) as executor:
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
            sock.settimeout(self.__timeout)
            result = sock.connect_ex((self.__target_host, port))

            if result == 0:
                print(f"Port {port}: Open")
                return port

        except Exception as e:
            print(f"Error scanning port {port}: {e}")

        finally:
            sock.close()


class PortScannerArgs:
    def __init__(self):
        self.parser = argparse.ArgumentParser(description="Port scanner")
        self.parser.add_argument("host", type=self.valid_hostname, help="Host to scan")
        self.parser.add_argument("start_port", type=self.valid_port, help="The Start port [1-65535]", metavar="Start_Port[1-65535]")
        self.parser.add_argument("end_port", type=self.valid_port, help="The End Port [1-65535]", metavar="End_Port[1-65535]")
        self.parser.add_argument("--timeout", help="Timeout (seconds)", type=int, default=1)
        self.parser.add_argument("-t","--threads", help="The number of threads to use for the port scans (default: 1, max: 100)", type=self.valid_threads, default=1)

    def parse_args(self):
        return self.parser.parse_args()

    def valid_port(self, value):
        port = int(value)
        if port < 1 or port > 65535:
            raise argparse.ArgumentTypeError(f"Invalid port number: {value}")
        return port

    def valid_threads(self, value):
        num_of_threads = int(value)
        if num_of_threads < 1 or num_of_threads > 100:
            raise argparse.ArgumentTypeError(f"Invalid number of threads: {value}. Please choose a value between 1-100")
        return num_of_threads

    def valid_hostname(self, hostname):
        pattern = r"^(?=.{1,255}$)[0-9a-zA-Z]([-\w]*[0-9a-zA-Z])*(\.[0-9a-zA-Z]([-\w]*[0-9a-zA-Z])*)+$"
        if not re.match(pattern, hostname):
            raise argparse.ArgumentTypeError(f"Invalid hostname: {hostname}")
        return hostname

if __name__ == "__main__":
    arg_parser = PortScannerArgs()
    args = arg_parser.parse_args()

    target_ip = socket.gethostbyname(args.host)
    scanner = PortScanner(args)
    open_ports = scanner.scan()
    print(f"Open ports: {open_ports}")
    print(target_ip)
