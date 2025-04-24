from scapy.all import rdpcap, sendp, Ether, IP, UDP
import time, argparse, os

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--print_only", action="store_true", help="Use --print_only to see the number of UDP packets that will be sent(will not send any package)")
    parser.add_argument("--file", type=str, required=True, help="Define the path to the file that will be replayed")

    return parser.parse_args()

def traffic_replay():
    args = parse_args()
    packets = rdpcap(os.path.join("junk_data", args.file))
    packet_send = 1
    lastindex = None

    for i, pkt in enumerate(packets):
        if pkt.haslayer("UDP"):
            if lastindex is not None and not args.print_only:
                delay = float(pkt.time - packets[lastindex].time)
                if delay >= 0.015:
                    time.sleep(delay)

            # Modify packet destination IP and remove checksums
            if IP in pkt:
                pkt[IP].dst = "127.0.0.1"
                del pkt[IP].chksum
            if UDP in pkt:
                del pkt[UDP].chksum

            # Wrap in Ethernet if missing
            if Ether not in pkt:
                pkt = Ether() / pkt

            if args.print_only:
                print(f"Packet number = {packet_send}")
            else:
                sendp(pkt, iface="Ethernet", verbose=False)

            packet_send += 1
            lastindex = i

if __name__ == "__main__":
    traffic_replay()
