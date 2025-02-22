import logging
import argparse
import os
import time
import threading
import socket
import struct
import src.settings as settings
from src.port_deceiver import PortDeceiver
from src.os_deceiver import OsDeceiver

# Configure Logging
logging.basicConfig(
    format='%(asctime)s [%(levelname)s]: %(message)s',
    datefmt='%y-%m-%d %H:%M',
    level=logging.DEBUG  # Use DEBUG for more details
)

def collect_fingerprint(target_host, dest, nic, max_packets=100):
    """
    Captures fingerprinting packets for the target host and classifies them into ARP, ICMP, TCP, UDP.
    """
    logging.info(f"Starting OS Fingerprinting on {target_host} (Max: {max_packets} packets)")

    # Ensure directory exists
    if not os.path.exists(dest):
        os.makedirs(dest)
    os_dest = os.path.join(dest, "unknown")
    if not os.path.exists(os_dest):
        os.makedirs(os_dest)

    # Enable promiscuous mode
    os.system(f"sudo ip link set {nic} promisc on")

    # Open socket to capture packets
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sock.bind((nic, 0))
    sock.settimeout(5)  # Timeout to prevent indefinite hanging

    target_ip = socket.inet_aton(target_host)
    packet_count = 0
    logging.info(f"Storing fingerprint data in: {os_dest}")

    # Open files to store categorized packets
    file_paths = {
        "arp": os.path.join(os_dest, "arp_record.txt"),
        "icmp": os.path.join(os_dest, "icmp_record.txt"),
        "tcp": os.path.join(os_dest, "tcp_record.txt"),
        "udp": os.path.join(os_dest, "udp_record.txt")
    }

    timeout = time.time() + 60  # Ensures scanning lasts at least 60 seconds

    while packet_count < max_packets and time.time() < timeout:
        try:
            packet, addr = sock.recvfrom(65565)
            logging.debug(f"[DEBUG] Packet received from {addr}")
            print(f"[DEBUG] Raw Packet Data: {packet.hex()[:100]}")  # Print first 100 bytes

            eth_protocol = struct.unpack("!H", packet[12:14])[0]
            proto_type = None

            if eth_protocol == 0x0806:  # ARP Packet
                proto_type = "arp"

            elif eth_protocol == 0x0800:  # IP Packet
                ip_header = packet[14:34]  # Extract IP header
                ip_proto = struct.unpack("!B", ip_header[9:10])[0]  # Extract protocol field

                src_ip = socket.inet_ntoa(ip_header[12:16])
                dest_ip = socket.inet_ntoa(ip_header[16:20])

                logging.debug(f"[DEBUG] Packet Type: IP | Src: {src_ip} -> Dest: {dest_ip} | Protocol: {ip_proto}")

                if src_ip != target_host and dest_ip != target_host:
                    logging.debug(f"[DEBUG] Packet ignored - Not from/to target {target_host}")
                    continue

                if ip_proto == 1:  # ICMP
                    proto_type = "icmp"
                    icmp_header = packet[34:42]  # Extract ICMP header
                    icmp_type, icmp_code, icmp_checksum = struct.unpack("!BBH", icmp_header[:4])

                    logging.debug(f"[DEBUG] ICMP Packet: Type={icmp_type}, Code={icmp_code}")

                elif ip_proto == 6:  # TCP
                    proto_type = "tcp"
                    tcp_header = packet[34:54]  # Extract TCP header
                    src_port, dest_port, seq, ack, offset_res_flags = struct.unpack("!HHLLH", tcp_header[:14])

                    logging.debug(f"[DEBUG] TCP Packet: {src_ip}:{src_port} -> {dest_ip}:{dest_port}")

                elif ip_proto == 17:  # UDP
                    proto_type = "udp"
                    udp_header = packet[34:42]  # Extract UDP header
                    src_port, dest_port, length, checksum = struct.unpack("!HHHH", udp_header)

                    logging.debug(f"[DEBUG] UDP Packet: {src_ip}:{src_port} -> {dest_ip}:{dest_port}")

            if proto_type:
                with open(file_paths[proto_type], "a") as f:
                    f.write(str(packet) + "\n")
                logging.info(f"Captured {proto_type.upper()} Packet ({packet_count + 1})")

            packet_count += 1

        except BlockingIOError:
            logging.warning("[WARNING] No packets received yet, retrying...")
            time.sleep(0.5)

        except socket.timeout:
            logging.warning("No packets received within timeout. Continuing scan...")
            continue  # Instead of exiting, it retries

        except Exception as e:
            logging.error(f"Unexpected error while receiving packets: {e}")
            break

    # Final check
    if packet_count == 0:
        logging.error("No packets captured! Check interface and network traffic.")
    else:
        logging.info(f"OS Fingerprinting Completed. Captured {packet_count} packets.")

def main():
    parser = argparse.ArgumentParser(description="Camouflage Cloak - OS Deception & Fingerprinting System")
    parser.add_argument("--host", required=True, help="Target host IP to deceive or fingerprint (e.g., 192.168.23.202)")
    parser.add_argument("--nic", required=True, help="Network interface to capture packets (e.g., ens192)")
    parser.add_argument("--scan", choices=["ts", "od", "rr", "pd"], required=True, help="Scanning technique")
    parser.add_argument("--status", help="Designate port status (used with --scan pd)")
    parser.add_argument("--os", help="Designate OS we want to deceive (required for --scan od)")
    parser.add_argument("--dest", required=True, help="Directory to store OS fingerprints")
    parser.add_argument("--te", type=int, help="Timeout duration in minutes for --od and --pd (e.g., --te 6 for 6 minutes)")
    
    args = parser.parse_args()

    settings.HOST = args.host
    settings.NIC = args.nic

    # Ensure destination directory exists
    if not os.path.exists(args.dest):
        os.makedirs(args.dest)

    logging.info(f"Starting deception tool with mode: {args.scan}")

    if args.scan == 'ts':
        logging.info(f"Executing OS Fingerprinting for {args.host}...")
        collect_fingerprint(target_host=args.host, dest=args.dest, nic=args.nic, max_packets=100)
        logging.info("Fingerprinting completed. Returning to command mode.")

    else:
        logging.error("Invalid scan technique specified.")
        return

if __name__ == '__main__':
    main()
