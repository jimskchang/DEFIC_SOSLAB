import logging
import argparse
import os
import threading
import socket
import struct
import src.settings as settings
import time
from src.os_deceiver import OsDeceiver

# Logging configuration
logging.basicConfig(
    format='%(asctime)s [%(levelname)s]: %(message)s',
    datefmt='%y-%m-%d %H:%M',
    level=logging.INFO
)

def collect_fingerprint(target_host, nic, dest, max_packets=100):
    """ Captures fingerprinting packets for the target host only. """
    
    logging.info(f"Starting OS Fingerprinting on {target_host} (Max: {max_packets} packets)")

    os.makedirs(dest, exist_ok=True)
    logging.info(f"Storing fingerprint data in: {dest}")

    # Open raw socket to capture packets
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    sock.bind((nic, 0))  
    sock.settimeout(10)  # Increase timeout to 10 seconds

    target_ip = socket.inet_aton(target_host)
    packet_count = 0

    timeout = time.time() + 120  # Increase overall scan time to 2 minutes

    while packet_count < max_packets and time.time() < timeout:
        try:
            packet, addr = sock.recvfrom(65565)
            logging.info(f"[DEBUG] Raw Packet Data (First 100 Bytes): {packet[:100].hex()}")

            eth_protocol = struct.unpack("!H", packet[12:14])[0]
            ip_header = packet[14:34]
            ip_unpack = struct.unpack("!BBHHHBBH4s4s", ip_header)
            src_ip = ip_unpack[8]
            dest_ip = ip_unpack[9]

            src_ip_str = socket.inet_ntoa(src_ip)
            dest_ip_str = socket.inet_ntoa(dest_ip)

            # Debug: Print packet details
            logging.info(f"Captured Packet: {src_ip_str} → {dest_ip_str} (Protocol: {eth_protocol})")

            if src_ip != target_ip and dest_ip != target_ip:
                logging.info("[DEBUG] Ignored packet (Not from/to target)")
                continue

            # Save packets
            proto_type = None
            if eth_protocol == 0x0806:
                proto_type = "arp"
            elif eth_protocol == 0x0800:
                ip_proto = packet[23]
                if ip_proto == 1:
                    proto_type = "icmp"
                elif ip_proto == 6:
                    proto_type = "tcp"
                elif ip_proto == 17:
                    proto_type = "udp"

            if proto_type:
                packet_file = os.path.join(dest, f"{proto_type}_record.txt")
                with open(packet_file, "a") as f:
                    f.write(str(packet) + "\n")
                packet_count += 1
                logging.info(f"Saved {proto_type.upper()} Packet ({packet_count})")

        except socket.timeout:
            logging.warning("No packets received in 10 seconds. Retrying...")
            continue  # Retry instead of breaking

        except Exception as e:
            logging.error(f"Error while capturing packets: {e}")
            break

    if packet_count == 0:
        logging.warning("No packets captured! Check network settings and traffic.")
    
    logging.info(f"OS Fingerprinting Completed. Captured {packet_count} packets.")
    

def execute_command(args):
    """ Executes a given command based on user input """
    settings.HOST = args.host
    settings.NIC = args.nic

    if args.scan == 'ts':
        os_dest = os.path.join("os_record", "unknown")  # Store in /os_record/unknown/
        os.makedirs(os_dest, exist_ok=True)  # Ensure the folder exists

        logging.info(f"Executing OS Fingerprinting for {args.host}...")
        collect_fingerprint(args.host, args.nic, os_dest, max_packets=100)

    elif args.scan == 'od':
        if not args.os or not args.te:
            logging.error("Missing required arguments: --os and --te are needed for --scan od")
            return

        os_dest = os.path.join("os_record", args.os)  # Store in correct OS folder
        os.makedirs(os_dest, exist_ok=True)

        logging.info(f"Executing OS Deception on {args.host}, mimicking {args.os}...")
        deceiver = OsDeceiver(args.host, args.os, dest=os_dest)
        deceiver.os_deceive()
        logging.info(f"OS Deception will run for {args.te} minutes...")
        timer = threading.Timer(args.te * 60, deceiver.stop)
        timer.start()

    else:
        logging.error("Invalid scan technique specified.")

def main():
    """ Main function with normal execution and optional command mode """
    parser = argparse.ArgumentParser(description='Deceiver Command Mode')
    parser.add_argument('--host', required=True, help='Target host IP')
    parser.add_argument('--nic', required=True, help='NIC where we capture packets')
    parser.add_argument('--scan', choices=['ts', 'od', 'rr', 'pd'], required=True, help='Scanning technique')
    parser.add_argument('--os', help='OS to mimic (required for --scan od)')
    parser.add_argument('--te', type=int, help='Timeout duration in minutes for --od')
    args = parser.parse_args()

    execute_command(args)

if __name__ == '__main__':
    main()
