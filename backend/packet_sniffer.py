from scapy.all import sniff, Raw
from scapy.layers.inet import IP
import argparse

def data_handler_callback(pkt):
    if IP in pkt: 
        print("i am moving", pkt)

def sniff_packets():
    print("I am sniffing")

    parser = argparse.ArgumentParser()
    parser.add_argument("--dev", action="store_true", help="Use --dev to fetch data in the loopback")
    args = parser.parse_args()

    if args.dev:
        # Dev mode (local replay)
        print("Starting to sniff in devmode")
        sniff(prn=data_handler_callback, iface="Ethernet", store=0, timeout=60)
    else:
        # Normal server mode
        print("Starting to sniff")
        sniff(prn=data_handler_callback, filter="ip", store=0)


if __name__ == "__main__":
    sniff_packets() 
