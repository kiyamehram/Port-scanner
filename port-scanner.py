import socket
import threading
import time
import ipaddress
import subprocess
import sys
import argparse
import json
import csv
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
import platform
import nmap
import logging
import ssl
import colorama
from colorama import Fore, Back, Style
import random
import os
from typing import Dict, List, Optional, Tuple

try:
    from scapy.all import sr1, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy is not installed. Some scan types will not be available.")


class AdvancedPortScanner:
    def __init__(self, target: str, ports: str = "1-1024", max_threads: int = 1000, 
                 timeout: float = 0.5, scan_types: List[str] = ['connect'], 
                 output_file: Optional[str] = None, output_format: str = 'json',
                 rate_limit: Optional[int] = None, service_detection: bool = False, 
                 os_detection: bool = False, stealth_level: int = 0,
                 spoof_source: bool = False, retry_count: int = 2,
                 tls_probing: bool = False, no_ping: bool = False):
        self.target = target
        self.start_port, self.end_port = self.parse_ports(ports)
        self.max_threads = max_threads
        self.timeout = timeout
        self.scan_types = scan_types
        self.output_file = output_file
        self.output_format = output_format.lower()
        self.rate_limit = rate_limit or 1000
        self.service_detection = service_detection
        self.os_detection = os_detection
        self.stealth_level = stealth_level  
        self.spoof_source = spoof_source
        self.retry_count = retry_count
        self.tls_probing = tls_probing
        self.no_ping = no_ping
        
        logging.basicConfig(level=logging.INFO, 
                          format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
        
        self.open_ports: List[int] = []
        self.scan_results: Dict[int, Dict] = {}
        self.lock = threading.Lock()
        self.host_up = False
        self.total_ports = self.end_port - self.start_port + 1
        self.platform = platform.system().lower()
        
        if service_detection or os_detection:
            try:
                self.nm = nmap.PortScanner()
            except Exception as e:
                self.logger.warning(f"Failed to initialize Nmap: {e}")
                self.nm = None
                self.service_detection = False
                self.os_detection = False
        else:
            self.nm = None
        
        self.rate_limiter = Queue(maxsize=self.rate_limit)
        
        self.common_services = {
            20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 67: 'dhcp', 68: 'dhcp', 69: 'tftp', 80: 'http', 
            110: 'pop3', 123: 'ntp', 135: 'msrpc', 139: 'netbios-ssn',
            143: 'imap', 161: 'snmp', 162: 'snmptrap', 389: 'ldap', 
            443: 'https', 445: 'smb', 993: 'imaps', 995: 'pop3s',
            1433: 'mssql', 1521: 'oracle', 1723: 'pptp', 1900: 'upnp',
            3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 5900: 'vnc',
            6000: 'x11', 6379: 'redis', 8080: 'http-alt', 8443: 'https-alt',
            27017: 'mongodb', 27018: 'mongodb', 27019: 'mongodb'
        }
        
        self.source_ip = self._get_random_source_ip() if spoof_source else None
        self.scan_start_time = None
        
    def _get_random_source_ip(self) -> str:
        return f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"

    def parse_ports(self, ports_str: str) -> Tuple[int, int]:
        try:
            if '-' in ports_str:
                start, end = map(int, ports_str.split('-'))
                return start, end
            elif ',' in ports_str:
                ports = list(map(int, ports_str.split(',')))
                return min(ports), max(ports)
            else:
                port = int(ports_str)
                return port, port
        except ValueError as e:
            self.logger.error(f"Invalid port specification: {ports_str}")
            sys.exit(1)

    def resolve_target(self) -> List[str]:
        try:
            if '/' in self.target:
                network = ipaddress.ip_network(self.target, strict=False)
                return [str(ip) for ip in network.hosts()]
            elif ',' in self.target:
                return [socket.gethostbyname(t.strip()) for t in self.target.split(',')]
            else:
                return [socket.gethostbyname(self.target)]
        except (socket.gaierror, ValueError) as e:
            self.logger.error(f"Error resolving target {self.target}: {e}")
            return []

    def host_discovery(self, target: str) -> bool:
        if self.no_ping:
            return True
            
        try:
            if self.platform.startswith("win"):
                ping_param = "-n 1 -w 2000"
            else:
                ping_param = "-c 1 -W 2"
                
            command = ["ping"] + ping_param.split() + [target]
            with open(os.devnull, 'w') as devnull:
                if subprocess.call(command, stdout=devnull, stderr=devnull) == 0:
                    return True
            
            for port in [80, 443, 22, 21]:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(1)
                        if s.connect_ex((target, port)) == 0:
                            return True
                except:
                    continue
                    
            return False
        except Exception as e:
            self.logger.warning(f"Host discovery failed for {target}: {e}")
            return True  

    def grab_banner(self, target: str, port: int) -> Optional[str]:
        try:
            with socket.create_connection((target, port), timeout=self.timeout) as s:
                s.settimeout(self.timeout)
                
                if port in [21, 22, 25, 110, 143]:
                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                    return banner[:200]
                
                elif port in [80, 443, 8080, 8443]:
                    if port in [443, 8443] or self.tls_probing:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        s = context.wrap_socket(s, server_hostname=target)
                    
                    s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    response = s.recv(1024).decode('utf-8', errors='ignore')
                    return response[:200].strip()
                
                else:
                    s.send(b'\r\n\r\n')
                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                    return banner[:200] if banner else None
                    
        except Exception:
            return None

    def scan_port_connect(self, target: str, port: int) -> Dict:
        for _ in range(self.retry_count):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    result = s.connect_ex((target, port))
                    if result == 0:
                        service = self.common_services.get(port, 'unknown')
                        banner = self.grab_banner(target, port) if self.service_detection else None
                        return {
                            'port': port,
                            'state': 'open',
                            'service': service,
                            'banner': banner,
                            'protocol': 'tcp'
                        }
                    return {'port': port, 'state': 'closed', 'service': None, 
                           'banner': None, 'protocol': 'tcp'}
            except socket.timeout:
                continue
            except Exception:
                continue
                
        return {'port': port, 'state': 'filtered', 'service': None, 
                'banner': None, 'protocol': 'tcp'}

    def scan_port_syn(self, target: str, port: int) -> Dict:
        if not SCAPY_AVAILABLE:
            self.logger.warning("Scapy not available, falling back to connect scan")
            return self.scan_port_connect(target, port)
            
        try:
            src_port = random.randint(1024, 65535)
            pkt = IP(dst=target, src=self.source_ip if self.spoof_source else None) / \
                  TCP(sport=src_port, dport=port, flags="S")
            
            response = sr1(pkt, timeout=self.timeout, verbose=0)
            
            if response and response.haslayer(TCP):
                if response[TCP].flags & 0x12:  
                    rst_pkt = IP(dst=target) / TCP(sport=src_port, dport=port, flags="R")
                    sr1(rst_pkt, timeout=0.1, verbose=0)
                    return {
                        'port': port,
                        'state': 'open',
                        'service': self.common_services.get(port, 'unknown'),
                        'banner': None,
                        'protocol': 'tcp'
                    }
                elif response[TCP].flags & 0x14:  
                    return {'port': port, 'state': 'closed', 'service': None, 
                           'banner': None, 'protocol': 'tcp'}
            return {'port': port, 'state': 'filtered', 'service': None, 
                   'banner': None, 'protocol': 'tcp'}
        except PermissionError:
            self.logger.warning("SYN scan requires root privileges. Falling back to CONNECT scan.")
            return self.scan_port_connect(target, port)
        except Exception as e:
            return {'port': port, 'state': 'error', 'service': None, 
                   'banner': str(e), 'protocol': 'tcp'}

    def scan_port_udp(self, target: str, port: int) -> Dict:
        if not SCAPY_AVAILABLE:
            self.logger.warning("Scapy not available, UDP scan not supported")
            return {'port': port, 'state': 'unsupported', 'service': None, 
                   'banner': None, 'protocol': 'udp'}
            
        try:
            src_port = random.randint(1024, 65535)
            pkt = IP(dst=target, src=self.source_ip if self.spoof_source else None) / \
                  UDP(sport=src_port, dport=port)
            
            response = sr1(pkt, timeout=self.timeout, verbose=0)
            
            if response is None:
                return {'port': port, 'state': 'open|filtered', 'service': None, 
                       'banner': None, 'protocol': 'udp'}
            elif response.haslayer(UDP):
                return {
                    'port': port,
                    'state': 'open',
                    'service': self.common_services.get(port, 'unknown'),
                    'banner': None,
                    'protocol': 'udp'
                }
            elif response.haslayer(ICMP):
                if int(response[ICMP].type) == 3 and int(response[ICMP].code) in (1, 2, 3, 9, 10, 13):
                    return {'port': port, 'state': 'closed', 'service': None, 
                           'banner': None, 'protocol': 'udp'}
            return {'port': port, 'state': 'open|filtered', 'service': None, 
                   'banner': None, 'protocol': 'udp'}
        except Exception as e:
            return {'port': port, 'state': 'error', 'service': None, 
                   'banner': str(e), 'protocol': 'udp'}

    def scan_port_xmas(self, target: str, port: int) -> Dict:
        if not SCAPY_AVAILABLE:
            self.logger.warning("Scapy not available, XMAS scan not supported")
            return {'port': port, 'state': 'unsupported', 'service': None, 
                   'banner': None, 'protocol': 'tcp'}
            
        try:
            src_port = random.randint(1024, 65535)
            pkt = IP(dst=target, src=self.source_ip if self.spoof_source else None) / \
                  TCP(sport=src_port, dport=port, flags="FPU")
            
            response = sr1(pkt, timeout=self.timeout, verbose=0)
            
            if response is None:
                return {
                    'port': port,
                    'state': 'open|filtered',
                    'service': None,
                    'banner': None,
                    'protocol': 'tcp'
                }
            elif response.haslayer(TCP) and response[TCP].flags & 0x14:
                return {
                    'port': port,
                    'state': 'closed',
                    'service': None,
                    'banner': None,
                    'protocol': 'tcp'
                }
            return {'port': port, 'state': 'open|filtered', 'service': None, 
                   'banner': None, 'protocol': 'tcp'}
        except Exception as e:
            return {'port': port, 'state': 'error', 'service': None, 
                   'banner': str(e), 'protocol': 'tcp'}

    def apply_stealth(self, scan_func):
        def wrapper(target: str, port: int) -> Dict:
            if self.stealth_level >= 1:
                time.sleep(random.uniform(0.01, 0.1 * self.stealth_level))
            
            if self.stealth_level >= 2:
                original_timeout = self.timeout
                self.timeout *= 0.5
                result = scan_func(target, port)
                self.timeout = original_timeout
                return result
                
            return scan_func(target, port)
        return wrapper

    def scan_port(self, target: str, port: int) -> Dict:
        scan_methods = {
            'connect': self.scan_port_connect,
            'syn': self.scan_port_syn,
            'udp': self.scan_port_udp,
            'xmas': self.scan_port_xmas
        }
        
        results = []
        for scan_type in self.scan_types:
            method = scan_methods.get(scan_type)
            if method:
                stealth_method = self.apply_stealth(method)
                result = stealth_method(target, port)
                results.append(result)
        
        if not results:
            return {'port': port, 'state': 'error', 'service': None, 
                   'banner': 'No valid scan methods', 'protocol': 'unknown'}
        
        combined = results[0]
        for r in results[1:]:
            if r['state'] == 'open':
                combined = r
                break
        return combined

    def perform_service_detection(self, target: str, ports: List[int]) -> None:
        if not self.service_detection or not ports or not self.nm:
            return
        
        try:
            ports_str = ','.join(str(p) for p in ports)
            arguments = '-sV --version-intensity 5'  
            self.nm.scan(target, ports=ports_str, arguments=arguments)
            
            if target not in self.nm.all_hosts():
                return
                
            for port in ports:
                if port in self.nm[target].get('tcp', {}):
                    service_info = self.nm[target]['tcp'][port]
                    with self.lock:
                        if port in self.scan_results:
                            self.scan_results[port].update({
                                'service': service_info.get('name', 'unknown'),
                                'version': f"{service_info.get('product', '')} {service_info.get('version', '')}".strip(),
                                'extra_info': service_info.get('extrainfo', ''),
                                'script_output': service_info.get('script', '')
                            })
        except Exception as e:
            self.logger.error(f"Service detection failed: {e}")

    def perform_os_detection(self, target: str) -> Optional[Dict]:
        if not self.os_detection or not self.nm:
            return None
        try:
            self.nm.scan(target, arguments='-O --osscan-guess')
            if target not in self.nm.all_hosts():
                return None
                
            os_info = self.nm[target].get('osmatch', [{}])
            if os_info:
                best_os = os_info[0]  
                return {
                    'os_name': best_os.get('name', 'unknown'),
                    'accuracy': best_os.get('accuracy', 'unknown'),
                    'os_type': best_os.get('osclass', [{}])[0].get('type', 'unknown'),
                    'vendor': best_os.get('osclass', [{}])[0].get('vendor', 'unknown'),
                    'os_family': best_os.get('osclass', [{}])[0].get('osfamily', 'unknown')
                }
            return None
        except Exception as e:
            self.logger.error(f"OS detection failed: {e}")
            return None

    def save_results(self, results: Dict, targets: List[str]) -> None:
        if not self.output_file:
            return
            
        try:
            output_data = {
                'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'scan_duration': f"{time.time() - self.scan_start_time:.2f}s",
                'targets': results,
                'os_info': {}
            }

            for target in targets:
                if target in results and any(p_info.get('state') == 'open' for p_info in results[target].values()):
                    output_data['os_info'][target] = self.perform_os_detection(target)

            if self.output_format == 'json':
                with open(self.output_file, 'w') as f:
                    json.dump(output_data, f, indent=4)
            
            elif self.output_format == 'csv':
                with open(self.output_file, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Target', 'Port', 'Protocol', 'State', 'Service', 
                                   'Version', 'Banner', 'Extra Info'])
                    for target, ports in results.items():
                        for port, info in ports.items():
                            writer.writerow([
                                target, port, info.get('protocol', ''), info['state'],
                                info.get('service', ''), info.get('version', ''),
                                info.get('banner', ''), info.get('extra_info', '')
                            ])
            
            elif self.output_format == 'xml':
                try:
                    from xml.etree.ElementTree import Element, SubElement, tostring
                    from xml.dom import minidom
                    
                    root = Element('scan')
                    root.set('time', output_data['scan_time'])
                    root.set('duration', output_data['scan_duration'])
                    
                    for target, ports in results.items():
                        target_elem = SubElement(root, 'target', ip=target)
                        for port, info in ports.items():
                            port_elem = SubElement(target_elem, 'port', number=str(port))
                            for key, value in info.items():
                                if key != 'port':  
                                    SubElement(port_elem, key).text = str(value)
                    
                    xmlstr = minidom.parseString(tostring(root)).toprettyxml(indent="  ")
                    with open(self.output_file, 'w') as f:
                        f.write(xmlstr)
                except ImportError:
                    self.logger.error("XML output requires ElementTree and minidom")
            
            elif self.output_format == 'txt':
                with open(self.output_file, 'w') as f:
                    f.write(f"Scan Time: {output_data['scan_time']}\n")
                    f.write(f"Scan Duration: {output_data['scan_duration']}\n\n")
                    
                    for target, ports in results.items():
                        f.write(f"Target: {target}\n")
                        f.write("PORT\tSTATE\tSERVICE\tVERSION\tBANNER\n")
                        f.write("----\t-----\t-------\t-------\t------\n")
                        
                        for port, info in sorted(ports.items(), key=lambda x: x[0]):
                            if info['state'] == 'open':
                                f.write(f"{port}\t{info['state']}\t{info.get('service', '')}\t"
                                       f"{info.get('version', '')}\t{info.get('banner', '')}\n")
                        f.write("\n")
            
            self.logger.info(f"Results saved to: {self.output_file}")
        except Exception as e:
            self.logger.error(f"Error saving results: {e}")

    def run_scan(self) -> None:
        self.scan_start_time = time.time()
        targets = self.resolve_target()
        if not targets:
            self.logger.error("No valid targets to scan")
            return

        results = {}
        for target in targets:
            self.logger.info(f"\nScanning target: {target}")
            self.logger.info(f"Port range: {self.start_port}-{self.end_port}")
            self.logger.info(f"Scan types: {', '.join(self.scan_types)}")
            self.logger.info(f"Max threads: {self.max_threads}")
            self.logger.info(f"Timeout: {self.timeout}s")
            
            if not self.host_discovery(target):
                self.logger.warning(f"Host {target} seems to be down")
                if not self.no_ping:
                    response = input("Continue anyway? (y/N): ")
                    if response.lower() != 'y':
                        continue

            self.scan_results = {}
            self.open_ports = []
            results[target] = {}

            if ('syn' in self.scan_types or 'udp' in self.scan_types or 'xmas' in self.scan_types) and not SCAPY_AVAILABLE:
                self.logger.warning("Scapy is not installed. Some scan types will fall back to connect scan.")
            
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                future_to_port = {
                    executor.submit(self.scan_port, target, port): port 
                    for port in range(self.start_port, self.end_port + 1)
                }

                completed = 0
                for future in as_completed(future_to_port):
                    if self.rate_limit:
                        self.rate_limiter.put(1)
                        self.rate_limiter.get()
                    
                    port = future_to_port[future]
                    try:
                        result = future.result()
                        with self.lock:
                            results[target][port] = result
                            if result['state'] == 'open':
                                self.open_ports.append(port)
                                self.scan_results[port] = result
                        
                        completed += 1
                        if completed % 100 == 0 or completed == self.total_ports:
                            progress = (completed / self.total_ports) * 100
                            print(f"\rProgress: {progress:.1f}% ({completed}/{self.total_ports})", end='')
                    except Exception as e:
                        self.logger.error(f"Error scanning port {port}: {e}")

            if self.service_detection and self.open_ports:
                self.perform_service_detection(target, self.open_ports)

            print("\n" + "-" * 60)
            self.logger.info(f"Scan completed for {target}")
            self.logger.info(f"Open ports found: {len(self.open_ports)}")
            if self.open_ports:
                print("\nDetailed results:")
                print("PORT\tPROTO\tSTATE\tSERVICE\tVERSION\tBANNER")
                for port in sorted(self.open_ports):
                    info = self.scan_results[port]
                    print(f"{port}\t{info.get('protocol', '')}\t{info['state']}\t"
                          f"{info.get('service', 'unknown')}\t{info.get('version', '')}\t"
                          f"{info.get('banner', '')}")

        if self.output_file:
            self.save_results(results, targets)

        print(f"\nTotal scan duration: {(time.time() - self.scan_start_time):.2f} seconds")


def parse_arguments():
    parser = argparse.ArgumentParser(description="Advanced Port Scanner")
    parser.add_argument("target", help="Target IP, hostname or network (CIDR)")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range to scan (e.g., 1-1000,80,443)")
    parser.add_argument("-t", "--threads", type=int, default=1000, help="Max threads")
    parser.add_argument("-T", "--timeout", type=float, default=0.5, help="Timeout in seconds")
    parser.add_argument("-s", "--scan-types", choices=['connect', 'syn', 'udp', 'xmas'], 
                       nargs='+', default=['connect'], help="Scan types")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("-f", "--format", choices=['json', 'csv', 'xml', 'txt'], 
                       default='json', help="Output format")
    parser.add_argument("-r", "--rate-limit", type=int, help="Max concurrent scans")
    parser.add_argument("--service-detection", action="store_true", 
                       help="Perform service version detection")
    parser.add_argument("--os-detection", action="store_true", 
                       help="Perform OS detection")
    parser.add_argument("--no-ping", action="store_true", 
                       help="Skip host discovery")
    parser.add_argument("--stealth", type=int, choices=[0, 1, 2], default=0,
                       help="Stealth level (0: none, 1: moderate, 2: high)")
    parser.add_argument("--spoof-source", action="store_true", 
                       help="Spoof source IP address")
    parser.add_argument("--retry-count", type=int, default=2,
                       help="Number of retry attempts for failed scans")
    parser.add_argument("--tls-probing", action="store_true",
                       help="Enable TLS probing for SSL/TLS services")
    
    return parser.parse_args()

colorama.init(autoreset=True)
def print_banner():
    print(f"""
{Fore.RED}[x] {Fore.WHITE}OPERATOR: {Fore.LIGHTBLACK_EX}[NoneR00tk1t]
{Fore.RED}[x] {Fore.WHITE}TEAM: {Fore.LIGHTBLACK_EX}[Valhala]
{Fore.LIGHTBLACK_EX}-------------------------------------
{Fore.RED}  ****           *   *
{Fore.RED} *  *************  **
{Fore.RED}*     *********    **
{Fore.RED}*     *  *         **
{Fore.RED} **  *  **         **
{Fore.RED}    *  ***         **  ***
{Fore.RED}   **   **         ** * ***
{Fore.RED}   **   **         ***   *
{Fore.RED}   **   **         **   *
{Fore.RED}   **   **         **  *
{Fore.RED}    **  **         ** **
{Fore.RED}     ** *      *   ******
{Fore.RED}      ***     *    **  ***
{Fore.RED}       *******     **   *** *
{Fore.RED}         ***        **   ***
{Fore.LIGHTBLACK_EX}-------------------------------------
{Style.RESET_ALL}
    """)

if __name__ == "__main__":
    print_banner()
    args = parse_arguments()
    
    if not SCAPY_AVAILABLE and any(st in ['syn', 'udp', 'xmas'] for st in args.scan_types):
        args.scan_types = ['connect']
    
    scanner = AdvancedPortScanner(
        target=args.target,
        ports=args.ports,
        max_threads=args.threads,
        timeout=args.timeout,
        scan_types=args.scan_types,
        output_file=args.output,
        output_format=args.format,
        rate_limit=args.rate_limit,
        service_detection=args.service_detection,
        os_detection=args.os_detection,
        stealth_level=args.stealth,
        spoof_source=args.spoof_source,
        retry_count=args.retry_count,
        tls_probing=args.tls_probing,
        no_ping=args.no_ping
    )
    
    try:
        scanner.run_scan()
    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[-] An error occurred: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
