import os
import logging
import socket
import struct
import time

def collect_fingerprint(target_host, nic, dest, max_packets=100):
    """
    Captures fingerprinting packets for the target host only.
    """
    logging.info(f"Starting OS Fingerprinting on {target_host} (Max: {max_packets} packets)")

    if not os.path.exists(dest):
        os.makedirs(dest)
    logging.info(f"Storing fingerprint data in: {dest}")

    try:
        logging.info(f"Creating RAW socket on interface {nic}...")
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        sock.bind((nic, 0))
        sock.settimeout(10)  # Set timeout to prevent indefinite blocking
        logging.info(f"Listening for packets on {nic}...")
    except Exception as e:
        logging.error(f"Failed to create or bind raw socket: {e}")
        return

    target_ip = socket.inet_aton(target_host)
    packet_count = 0

    timeout = time.time() + 120  # Set a total scan time of 2 minutes

    while packet_count < max_packets and time.time() < timeout:
        try:
            logging.info("[DEBUG] Waiting to receive a packet...")
            packet, addr = sock.recvfrom(65565)
            logging.info(f"[DEBUG] Packet received from {addr}")

            eth_protocol = struct.unpack("!H", packet[12:14])[0]
            ip_header = packet[14:34]
            ip_unpack = struct.unpack("!BBHHHBBH4s4s", ip_header)
            src_ip = ip_unpack[8]
            dest_ip = ip_unpack[9]

            src_ip_str = socket.inet_ntoa(src_ip)
            dest_ip_str = socket.inet_ntoa(dest_ip)

            logging.info(f"[DEBUG] Captured Packet: {src_ip_str} → {dest_ip_str} (Protocol: {eth_protocol})")

            if src_ip != target_ip and dest_ip != target_ip:
                logging.info("[DEBUG] Ignored packet (Not from/to target)")
                continue  # Ignore packets not meant for the target host

            # Save packet based on protocol
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
                logging.info(f"[DEBUG] Saved {proto_type.upper()} Packet ({packet_count})")

        except socket.timeout:
            logging.warning("[DEBUG] No packets received in 10 seconds. Retrying...")
            continue

        except Exception as e:
            logging.error(f"[ERROR] Unexpected error while capturing packets: {e}")
            break

    if packet_count == 0:
        logging.warning("[WARNING] No packets captured! Check network settings and traffic.")

    logging.info(f"OS Fingerprinting Completed. Captured {packet_count} packets.")
