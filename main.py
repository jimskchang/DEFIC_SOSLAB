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
    level=logging.INFO
)

def collect_fingerprint(target_host, dest, nic, max_packets=100):
    """
    Captures fingerprinting packets for the target host only.
    """
    logging.info(f"Starting OS Fingerprinting on {target_host} (Max: {max_packets} packets)")

    # Ensure directory exists
    if not os.path.exists(dest):
        os.makedirs(dest)
    if not os.path.exists(os.path.join(dest, 'unknown')):
        os.makedirs(os.path.join(dest, 'unknown'))

    # Enable promiscuous mode
    os.system(f"sudo ip link set {nic} promisc on")
    
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sock.bind((nic, 0))
    sock.settimeout(5)  # Timeout to prevent indefinite hanging

    target_ip = socket.inet_aton(target_host)
    packet_count = 0
    os_dest = os.path.join(dest, "unknown")
    logging.info(f"Storing fingerprint data in: {os_dest}")

    timeout = time.time() + 60  # Ensures scanning lasts at least 60 seconds

    while packet_count < max_packets and time.time() < timeout:
        try:
            packet, addr = sock.recvfrom(65565)
            logging.info(f"[DEBUG] Packet received from {addr}")
            print(f"[DEBUG] Raw Packet Data: {packet.hex()[:100]}")  # Print first 100 bytes

            eth_protocol = struct.unpack("!H", packet[12:14])[0]
            logging.info(f"[DEBUG] Eth Protocol: {eth_protocol:#06x}")

            # Store the captured packet
            with open(os.path.join(os_dest, "captured_packets.txt"), "a") as f:
                f.write(str(packet) + "\n")

            packet_count += 1
            logging.info(f"Captured {packet_count} packets so far...")

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
        logging.info(f"Storing OS response fingerprint for {args.host}...")
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
