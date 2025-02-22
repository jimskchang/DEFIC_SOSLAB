import logging
import argparse
import os
import time
import socket
import struct
import threading
import src.settings as settings
from src.port_deceiver import PortDeceiver
from src.os_deceiver import OsDeceiver

# Configure logging
logging.basicConfig(
    format='%(asctime)s [%(levelname)s]: %(message)s',
    datefmt='%y-%m-%d %H:%M',
    level=logging.DEBUG  # Use DEBUG mode for live packet analysis
)

def collect_fingerprint(target_host, dest, nic, max_packets=100):
    """
    Captures fingerprinting packets for the target host only.
    """
    logging.info(f"Starting OS Fingerprinting on {target_host} (Max: {max_packets} packets)")

    # Ensure necessary directories exist
    os.makedirs(dest, exist_ok=True)
    os.makedirs(os.path.join(dest, 'unknown'), exist_ok=True)

    # Enable promiscuous mode for better packet capturing
    os.system(f"sudo ip link set {nic} promisc on")
    logging.info("Waiting 2 seconds for promiscuous mode to take effect...")
    time.sleep(2)  # Short delay to ensure NIC is ready

    # Open RAW socket for capturing
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        sock.bind((nic, 0))
    except Exception as e:
        logging.error(f"Error opening raw socket: {e}")
        return

    target_ip = socket.inet_aton(target_host)
    packet_count = 0
    os_dest = os.path.join(dest, "unknown")
    logging.info(f"Storing fingerprint data in: {os_dest}")

    # Define packet type files
    packet_files = {
        "arp": os.path.join(os_dest, "arp_record.txt"),
        "icmp": os.path.join(os_dest, "icmp_record.txt"),
        "tcp": os.path.join(os_dest, "tcp_record.txt"),
        "udp": os.path.join(os_dest, "udp_record.txt"),
    }

    # **Loop to capture packets for 3 minutes**
    timeout = time.time() + 180  # 180 seconds (3 minutes)
    while packet_count < max_packets and time.time() < timeout:
        try:
            packet, addr = sock.recvfrom(65565)
            eth_protocol = struct.unpack("!H", packet[12:14])[0]
            proto_type = None

            # **Live Debugging Output**
            logging.debug(f"Captured raw packet ({len(packet)} bytes): {packet.hex()[:100]}")

            # **Detect ARP**
            if eth_protocol == 0x0806:
                proto_type = "arp"

            # **Detect IPv4 Traffic (Check IP Protocol Type)**
            elif eth_protocol == 0x0800:
                ip_proto = packet[23]
                if ip_proto == 1:
                    proto_type = "icmp"
                elif ip_proto == 6:
                    proto_type = "tcp"
                elif ip_proto == 17:
                    proto_type = "udp"

            # **Write Captured Packets to Files**
            if proto_type:
                with open(packet_files[proto_type], "a") as f:
                    f.write(str(packet) + "\n")
                packet_count += 1
                logging.info(f"Captured {proto_type.upper()} Packet ({packet_count})")

        except socket.timeout:
            logging.warning("No packets received within timeout. Waiting for more traffic...")
            time.sleep(2)  # Allow more time for packets
        except Exception as e:
            logging.error(f"Error while receiving packets: {e}")
            break

    if packet_count == 0:
        logging.warning("No packets captured! Check network interface settings and traffic.")
    else:
        logging.info(f"OS Fingerprinting Completed. Captured {packet_count} packets.")

def main():
    parser = argparse.ArgumentParser(description="Camouflage Cloak - OS Deception & Fingerprinting System")
    parser.add_argument("--host", required=True, help="Target host IP to deceive or fingerprint (e.g., 192.168.23.201)")
    parser.add_argument("--nic", required=True, help="Network interface to capture packets (e.g., ens192)")
    parser.add_argument("--scan", choices=["ts", "od", "rr", "pd"], required=True, help="Scanning technique")
    parser.add_argument("--status", help="Port status (used with --scan pd)")
    parser.add_argument("--os", help="OS to mimic (required for --scan od)")
    parser.add_argument("--dest", required=True, help="Directory to store OS fingerprints")
    parser.add_argument("--te", type=int, help="Timeout duration in minutes for --od and --pd")
    
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
        logging.info(f"Fingerprinting completed. Data stored in {args.dest}")
    
    elif args.scan == 'od':
        if not args.os:
            logging.error("Missing required argument: --os is needed for --scan od")
            return
        if not args.te:
            logging.error("Missing required argument: --te is needed for --scan od")
            return
        logging.info(f"Executing OS Deception on {args.host}, mimicking {args.os}...")
        deceiver = OsDeceiver(args.host, args.os)
        deceiver.os_deceive()
        logging.info(f"OS Deception will run for {args.te} minutes...")
        timer = threading.Timer(args.te * 60, deceiver.stop)
        timer.start()
    
    elif args.scan == 'rr':
        logging.info(f"Storing OS response fingerprint for {args.host} in {args.dest}...")
        deceiver = OsDeceiver(args.host, "unknown")
        deceiver.store_rsp()
        logging.info("OS response stored.")
    
    elif args.scan == 'pd':
        if not args.status:
            logging.error("Missing required argument: --status is needed for --scan pd")
            return
        if not args.te:
            logging.error("Missing required argument: --te is needed for --scan pd")
            return
        logging.info(f"Executing Port Deception on {args.host}, setting ports to {args.status}...")
        deceiver = PortDeceiver(args.host)
        deceiver.deceive_ps_hs(args.status)
        logging.info(f"Port Deception will run for {args.te} minutes...")
        timer = threading.Timer(args.te * 60, deceiver.stop)
        timer.start()
    
    else:
        logging.error("Invalid scan technique specified.")
        return

if __name__ == '__main__':
    main()
