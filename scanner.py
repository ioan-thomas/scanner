# Import the required modules
import logging                     # for logging
import socket                      # for creating sockets and resolving hostnames
from concurrent.futures import ThreadPoolExecutor, as_completed  # for concurrent execution of port scans
import argparse                    # for parsing the command-line arguments
from tqdm import tqdm              # for the progress bar
from vulnerable_ports import TOP_VULN_PORTS

# Configure logging
logging.basicConfig(level=logging.INFO)  # set the logging level to INFO
logger = logging.getLogger(__name__)      # create a logger with the current module's name

class PortScanner:
    def __init__(self, args, vuln_ports):
        # Initialize instance variables with the values from the args object
        self.__hosts = args.hosts
        self.__start_port = args.start_port
        self.__end_port = args.end_port
        self.__timeout = args.timeout
        self.__max_workers = args.threads
        self.__vuln_ports = vuln_ports
        self.__scan_vuln_ports = args.scan_vuln_ports

    def scan(self):
        # Loop through each host and scan its open ports
        for host in self.__hosts:
            try:
                # Resolve the IP address for the current host
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.__timeout)
                    target_ip = socket.gethostbyname(host)
            except socket.gaierror as e:
                # Log an error message if the hostname can't be resolved and continue to the next host
                logger.error(f"Error resolving hostname {host}: {e}")
                continue
            # Log a message indicating that scanning has started for the current host
            logger.info(f"Scanning {host} ({target_ip})")
            # Scan the open ports for the current host
            open_ports = self.__scan_host(target_ip)
            # Log the open ports for the current host
            logger.info(f"Open ports for {host} ({target_ip}): {open_ports}\n")

    def __scan_host(self, target_ip):
        open_ports = []
        with ThreadPoolExecutor(max_workers=self.__max_workers) as executor:
            # Determine which ports to scan
            futures = {executor.submit(self.__scan_port, target_ip, port): 
                    port for port in (self.__vuln_ports 
                                        if self.__scan_vuln_ports 
                                        else range(self.__start_port, self.__end_port + 1)
                                        )
                        }
            try:
                # Use tqdm to show a progress bar while the port scans are in progress
                with tqdm(total=len(futures), 
                        desc=f"Scanning {target_ip}", 
                        ncols=100, unit="port") as progress:
                    # Loop through each port being scanned and check if it's open
                    for future in as_completed(futures):
                        open_port = future.result()
                        if open_port is not None:
                            open_ports.append(open_port)
                        progress.update()
            except KeyboardInterrupt:
                # If the user presses Ctrl-C, stop the scan and log a warning message
                logger.warning("Stopping scan... Please wait for threads to finish.")
                executor._threads.clear()
            except Exception as e:
                # If there's an exception during the port scan, log an error message
                logger.exception(f"Error: {e}")
        return open_ports

    def __scan_port(self, target_ip, port):
        # Connect to the specified port and return the port number if it's open
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.__timeout)
            try:
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    return port
            except Exception as e:
                # Log an error message if there's an exception during the port scan and continue
                logger.exception(f"Error scanning port {port}: {e}")

class PortScannerArgs:
    # Parse the command-line arguments
    def __init__(self):
        self.__parser = argparse.ArgumentParser(description="Port scanner")
        self.__parser.add_argument("hosts", type=str, nargs='+', help="Hosts to scan (space-separated)")
        self.__parser.add_argument("start_port", type=int, help="The Start port [1-65535]", metavar="Start_Port[1-65535]", choices=range(1, 65536))
        self.__parser.add_argument("end_port", type=int, help="The End Port [1-65535]", metavar="End_Port[1-65535]", choices=range(1, 65536))
        self.__parser.add_argument("--timeout", help="Timeout (seconds) for DNS and connecting to ports", type=int, default=1)
        self.__parser.add_argument("-t", "--threads", help="The number of threads to use for the port scans (default: 1, max: 100)", type=int, default=1, choices=range(1, 101))
        self.__parser.add_argument("--scan-vuln-ports", help="Scan the top vulnerable ports (default: False)", action="store_true")
        
    def parse_args(self):
        # returning the parsed arguments
        return self.__parser.parse_args()
    
# runs the program if it's executed directly i.e. in the main module
if __name__ == "__main__":
    # Create a PortScanner object and scan the ports
    args = PortScannerArgs().parse_args()
    scanner = PortScanner(args, TOP_VULN_PORTS)
    scanner.scan()
