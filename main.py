import logging
import argparse
import os
import time
import socket
import struct
import src.settings as settings

# Configure Logging
logging.basicConfig(
    format='%(asctime)s [%(levelname)s]: %(message)s',
    datefmt='%y-%m-%d %H:%M',
    level=logging.DEBUG
)

def collect_fingerprint(target_host, dest, nic, max_packets=100):
    logging.info(f"Starting OS Fingerprinting on {target_host} (Max: {max_packets} packets)")

    # Ensure directories exist
    os.makedirs(dest, exist_ok=True)
    os_dest = os.path.join(dest, "unknown")
    os.makedirs(os_dest, exist_ok=True)

    # Enable promiscuous mode on NIC
    os.system(f"sudo ip link set {nic} promisc on")

    # Open raw socket
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        sock.bind((nic, 0))  # Ensure binding to correct NIC
    except Exception as e:
        logging.error(f"Failed to bind to interface {nic}: {e}")
        return

    sock.settimeout(10)
    packet_count = 0
    timeout = time.time() + 120

    logging.info(f"Storing fingerprint data in: {os_dest}")
    logging.info("Listening for packets...")

    # File paths
    file_paths = {
        "arp": os.path.join(os_dest, "arp_record.txt"),
        "icmp": os.path.join(os_dest, "icmp_record.txt"),
        "tcp": os.path.join(os_dest, "tcp_record.txt"),
        "udp": os.path.join(os_dest, "udp_record.txt")
    }

    while packet_count < max_packets and time.time() < timeout:
        try:
            packet, addr = sock.recvfrom(65565)
            eth_protocol = struct.unpack("!H", packet[12:14])[0]

            logging.debug(f"[DEBUG] Packet from {addr} - Protocol: {eth_protocol}")
            print(f"[DEBUG] Raw Packet: {packet.hex()[:100]}")  

            proto_type = None

            if eth_protocol == 0x0806:
                print("[DEBUG] ARP Packet detected")
                proto_type = "arp"

            elif eth_protocol == 0x0800:
                ip_proto = struct.unpack("!B", packet[23:24])[0]
                print(f"[DEBUG] IP Packet detected - Protocol: {ip_proto}")

                if ip_proto == 1:
                    print("[DEBUG] ICMP Packet detected")
                    proto_type = "icmp"

                elif ip_proto == 6:
                    print("[DEBUG] TCP Packet detected")
                    proto_type = "tcp"

                elif ip_proto == 17:
                    print("[DEBUG] UDP Packet detected")
                    proto_type = "udp"

            if proto_type:
                with open(file_paths[proto_type], "a") as f:
                    f.write(str(packet) + "\n")
                logging.info(f"Captured {proto_type.upper()} Packet ({packet_count + 1})")
                packet_count += 1  

        except socket.timeout:
            logging.warning("No packets received within timeout. Retrying...")
            continue  

        except Exception as e:
            logging.error(f"Unexpected error while receiving packets: {e}")
            break

    if packet_count == 0:
        logging.error("No packets captured! Check interface and network traffic.")
    else:
        logging.info(f"OS Fingerprinting Completed. Captured {packet_count} packets.")

def main():
    parser = argparse.ArgumentParser(description="Camouflage Cloak - OS Deception & Fingerprinting System")
    parser.add_argument("--host", required=True, help="Target host IP (e.g., 192.168.23.202)")
    parser.add_argument("--nic", required=True, help="Network interface (e.g., ens192)")
    parser.add_argument("--scan", choices=["ts"], required=True, help="Scanning technique")
    parser.add_argument("--dest", required=True, help="Directory to store OS fingerprints")

    args = parser.parse_args()

    settings.HOST = args.host
    settings.NIC = args.nic

    os.makedirs(args.dest, exist_ok=True)

    logging.info(f"Starting tool with mode: {args.scan}")

    if args.scan == 'ts':
        logging.info(f"Executing OS Fingerprinting for {args.host}...")
        collect_fingerprint(target_host=args.host, dest=args.dest, nic=args.nic, max_packets=100)
        logging.info("Fingerprinting completed. Returning to command mode.")

if __name__ == '__main__':
    main()
