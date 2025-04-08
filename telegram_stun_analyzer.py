import ipaddress
import netifaces
import requests
import argparse
import platform
import pyshark
import socket
import sys
import os
from typing import Optional, Dict, List
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Telegram AS list of excluded IP ranges
EXCLUDED_NETWORKS = [
    '91.108.13.0/24', '149.154.160.0/21', '149.154.160.0/22',
    '149.154.160.0/23', '149.154.162.0/23', '149.154.164.0/22',
    '149.154.164.0/23', '149.154.166.0/23', '149.154.168.0/22',
    '149.154.172.0/22', '185.76.151.0/24', '91.105.192.0/23',
    '91.108.12.0/22', '91.108.16.0/22', '91.108.20.0/22',
    '91.108.4.0/22', '91.108.56.0/22', '91.108.56.0/23',
    '91.108.58.0/23', '95.161.64.0/20'
    # Removed '91.108.8.0/22' to allow 91.108.9.83
]

def check_tshark_availability() -> None:
    """Check if Tshark is installed and available."""
    tshark_path = os.popen('which tshark').read().strip()
    if not tshark_path:
        print(Fore.RED + "[!] tshark is not installed. Install it using:")
        print(Fore.RED + "    sudo apt update && sudo apt install tshark")
        sys.exit(1)
    else:
        print(Fore.GREEN + "[+] tshark is available.")

def get_hostname(ip: str) -> Optional[str]:
    """Retrieve hostname for the given IP."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None

def get_my_ip() -> Optional[str]:
    """Retrieve the external IP address."""
    try:
        return requests.get('https://icanhazip.com').text.strip()
    except Exception as e:
        print(Fore.RED + f"[!] Error fetching external IP: {e}")
        return None

def get_whois_info(ip: str) -> Optional[Dict]:
    """Retrieve WHOIS data for the given IP."""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(Fore.RED + f"[!] Error fetching WHOIS data from API: {e}")
        return None

def display_whois_info(data: Dict) -> None:
    """Display the fetched WHOIS data."""
    if not data:
        print(Fore.RED + "[!] No WHOIS data available.")
        return

    print(Fore.CYAN + "\n[+] WHOIS Information:")
    print(Fore.CYAN + f"    Country: {data.get('country', 'N/A')}")
    print(Fore.CYAN + f"    Country Code: {data.get('countryCode', 'N/A')}")
    print(Fore.CYAN + f"    Region: {data.get('region', 'N/A')}")
    print(Fore.CYAN + f"    Region Name: {data.get('regionName', 'N/A')}")
    print(Fore.CYAN + f"    City: {data.get('city', 'N/A')}")
    print(Fore.CYAN + f"    Zip Code: {data.get('zip', 'N/A')}")
    print(Fore.CYAN + f"    Latitude: {data.get('lat', 'N/A')}")
    print(Fore.CYAN + f"    Longitude: {data.get('lon', 'N/A')}")
    print(Fore.CYAN + f"    Time Zone: {data.get('timezone', 'N/A')}")
    print(Fore.CYAN + f"    ISP: {data.get('isp', 'N/A')}")
    print(Fore.CYAN + f"    Organization: {data.get('org', 'N/A')}")
    print(Fore.CYAN + f"    AS: {data.get('as', 'N/A')}")

def is_excluded_ip(ip: str) -> bool:
    """Check if IP is in the excluded list."""
    for network in EXCLUDED_NETWORKS:
        if ipaddress.ip_address(ip) in ipaddress.ip_network(network):
            print(Fore.YELLOW + f"[!] Excluded IP {ip} (matches network {network})")
            return True
    return False

def choose_interface() -> str:
    """Prompt the user to select a network interface."""
    interfaces = netifaces.interfaces()
    print(Fore.YELLOW + "\n[+] Available interfaces:")
    for idx, iface in enumerate(interfaces, 1):
        print(Fore.YELLOW + f"{idx}. {iface}")
        try:
            ip_address = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
            mac_address = netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]['addr']
            print(Fore.YELLOW + f"    IP Address: {ip_address}, MAC Address: {mac_address}")
        except KeyError:
            print(Fore.RED + "    Unable to retrieve IP/MAC address for this interface.")

    choice = int(input(Fore.GREEN + "\n[+] Enter the number of the interface you want to use: "))
    return interfaces[choice - 1]

def extract_stun_xor_mapped_address(interface: str, packet_count: int, verbose: bool = False) -> Optional[str]:
    """Capture packets and extract the IP address from STUN protocol."""
    print(Fore.BLUE + f"[+] Capturing {packet_count} packets on interface {interface}, please wait...")
    cap = pyshark.LiveCapture(interface=interface, display_filter="stun")
    my_ip = get_my_ip()
    resolved = {}
    whois = {}

    try:
        for packet in cap.sniff_continuously(packet_count=packet_count):
            if verbose:
                print(Fore.MAGENTA + f"\n[+] Packet Details:")
                print(Fore.MAGENTA + f"    Protocol: {packet.highest_layer}")
                if hasattr(packet, 'ip'):
                    print(Fore.MAGENTA + f"    Source IP: {packet.ip.src}")
                    print(Fore.MAGENTA + f"    Destination IP: {packet.ip.dst}")
                if hasattr(packet, 'udp'):
                    print(Fore.MAGENTA + f"    Source Port: {packet.udp.srcport}")
                    print(Fore.MAGENTA + f"    Destination Port: {packet.udp.dstport}")

            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst

                if is_excluded_ip(src_ip):
                    print(Fore.YELLOW + f"[!] Excluded source IP: {src_ip}")
                    continue
                if is_excluded_ip(dst_ip):
                    print(Fore.YELLOW + f"[!] Excluded destination IP: {dst_ip}")
                    continue

                if src_ip not in resolved:
                    resolved[src_ip] = f"{src_ip}({get_hostname(src_ip) or 'N/A'})"
                if dst_ip not in resolved:
                    resolved[dst_ip] = f"{dst_ip}({get_hostname(dst_ip) or 'N/A'})"
                if src_ip not in whois:
                    whois[src_ip] = get_whois_info(src_ip)
                if dst_ip not in whois:
                    whois[dst_ip] = get_whois_info(dst_ip)

                if packet.stun:
                    xor_mapped_address = packet.stun.get_field_value('stun.att.ipv4') or packet.stun.get_field_value('stun.att.ipv6')
                    if verbose:
                        print(Fore.MAGENTA + f"\n[+] STUN Packet Details:")
                        print(Fore.MAGENTA + f"    Source: {resolved[src_ip]} ({whois[src_ip].get('org', 'N/A')})")
                        print(Fore.MAGENTA + f"    Destination: {resolved[dst_ip]} ({whois[dst_ip].get('org', 'N/A')})")
                        print(Fore.MAGENTA + f"    XOR-MAPPED-ADDRESS: {xor_mapped_address}")
                        for field in packet.stun._all_fields:
                            print(Fore.MAGENTA + f"    {field} = {packet.stun.get_field_value(field)}")

                    if xor_mapped_address and xor_mapped_address != my_ip:
                        return xor_mapped_address
    except KeyboardInterrupt:
        print(Fore.RED + "\n[+] Capture interrupted by user.")
    except Exception as e:
        print(Fore.RED + f"[!] Error during packet capture: {e}")

    return None

def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Determine the IP address of the interlocutor in the Telegram messenger.',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        '-i', '--interface',
        help='Network interface to use (e.g., eth0, wlan0). If not provided, a list of available interfaces will be shown.',
        default=None
    )
    parser.add_argument(
        '-c', '--count',
        type=int,
        help='Number of packets to capture (default: 100).',
        default=100
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose mode for detailed packet analysis.'
    )
    parser.add_argument(
        '-t', '--timeout',
        type=int,
        help='Capture timeout in seconds (default: 60).',
        default=60
    )
    parser.add_argument(
        '-o', '--output',
        help='Save output to a file (e.g., output.txt).',
        default=None
    )
    return parser.parse_args()

def main() -> None:
    try:
        check_tshark_availability()
        args = parse_arguments()

        interface_name = args.interface if args.interface else choose_interface()
        address = extract_stun_xor_mapped_address(interface_name, args.count, args.verbose)

        if address:
            print(Fore.GREEN + f"\n[+] SUCCESS! Found XOR-MAPPED-ADDRESS: {address}")
            whois_data = get_whois_info(address)
            display_whois_info(whois_data)

            if args.output:
                with open(args.output, 'w') as f:
                    f.write(f"XOR-MAPPED-ADDRESS: {address}\n")
                    f.write(f"WHOIS Information:\n")
                    f.write(f"Country: {whois_data.get('country', 'N/A')}\n")
                    f.write(f"ISP: {whois_data.get('isp', 'N/A')}\n")
                    f.write(f"Organization: {whois_data.get('org', 'N/A')}\n")
                    f.write(f"AS: {whois_data.get('as', 'N/A')}\n")
                print(Fore.GREEN + f"[+] Output saved to {args.output}")
        else:
            print(Fore.RED + "\n[!] Couldn't determine the IP address of the peer.")
    except (KeyboardInterrupt, EOFError):
        print(Fore.RED + "\n[+] Exiting gracefully...")
    except Exception as e:
        print(Fore.RED + f"[!] An error occurred: {e}")

if __name__ == "__main__":
    main()
