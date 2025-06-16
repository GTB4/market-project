from scapy.all import sniff, Raw
from scapy.layers.inet import IP, UDP
from data_handler import assemble_payload
import argparse, sys, re, json

#TEMP CODE!!! 
first_packet_count = 0
last_packet_count = 0
packet_count = 1
is_payload = False
packet_count = 0
payload_number = 1
payload_count = 1
last_payload = None
full_payload = b''
packet_fragments = {}


def data_handler_callback(pkt):

    # TEMP CODE!!
    global first_packet_count, last_packet_count, payload_number #Number
    global is_payload #Bool
    global last_payload
    global payload_count
    global full_payload
    global packet_fragments
    first_payload = False

    if IP in pkt: 
        if pkt[IP].src == "5.188.125.28" and UDP in pkt and Raw in pkt:
            raw_data = pkt[Raw].load
            if last_payload != raw_data:  
                last_payload = raw_data #Maybe at the end?? 

                # 00 79 00 32 73 02
                if b"\x00\x79\x00\x32\x73\x02" in raw_data:
                    is_payload = True
                    first_payload = True
                    # full_payload = b'00'
                    # payload_count = 1
                    print(f"Found first data {payload_count}")

                if is_payload:
                    if first_payload == True:
                        i = 0
                        start_i_payload = raw_data.find(b'\x7b\x22\x49\x64\x22')
                        packet_fragments[i] = raw_data[start_i_payload-2:]
                        first_payload = False
                    else:
                        i = raw_data[35]

                    if i not in packet_fragments : 
                        clean_payload = raw_data[44:]
                        packet_fragments[i] = clean_payload
                        # print(f"i have {i} payoad \n packet_fragments = \n {packet_fragments[i]}")
                    
                        # full_payload = full_payload + clean_payload 

                        # print(f"payload number : {payload_number}")

                    if payload_number == 26:

                        for key in list(packet_fragments):
                            if key < 0 or key > 25:
                                del packet_fragments[key]
                                
                        # Display every data in the dictionary before sending to data_handler
                        # for i in sorted(packet_fragments):
                        #     print(f"packet_fragments {i} :\n {packet_fragments[i]} \n")

                        assemble_payload(packet_fragments, payload_count)

                        is_payload = False
                        payload_number = 1
                        payload_count += 1
                        packet_fragments = {}



                        # THIS IS OLD WORKING CODE NO DELET !!!!!!!!!!!!!!!!!!!!
                        # i = full_payload.find(b'\x7b\x22\x49\x64\x22')
                        # full_payload = full_payload[i-2:]
                        # # clean_data(full_payload, payload_count)
                        # payload_count += 1
                        # is_payload = False
                        # payload_number = 1
                        # full_payload = b'00'
                        # print(f"packet_fragments : {packet_fragments}")
                    else:
                        payload_number += 1


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dev", action="store_true", help="Use --dev to fetch data in the loopback")
    parser.add_argument("--count", type=int, default=0, help="Number of packets to sniff before stopping (must be > 0)")
    parser.add_argument("--timeout", type=int, default=None, help="Time (in seconds) to sniff before stopping (must be > 0 if provided)")
    
    args = parser.parse_args()

    if args.dev and (args.count == 0 and args.timeout is None):
        parser.error("When using --dev, you must provide --count or --timeout (or both) with strictly positive values.")

    if args.count < 0:
        parser.error("--count must be a strictly positive integer")

    if args.timeout is not None and args.timeout <= 0:
        parser.error("--timeout must be a strictly positive integer")

    return args

def sniff_packets():
    print("I am sniffing")

    args = parse_args()

    if args.dev:
        print("Starting to sniff in devmode")
        sniff(prn=data_handler_callback, iface="Ethernet", store=0, count=args.count, timeout=args.timeout)
    else:
        print("Starting to sniff")
        sniff(prn=data_handler_callback, filter="ip", store=0)

if __name__ == "__main__":
    sniff_packets() 
