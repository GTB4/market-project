from scapy.all import rdpcap, sendp, Ether, IP, UDP
import time

def traffic_replay():

    packets = rdpcap(r"junk_data\leather_armor_t6.pcap")
    lastindex = None

    for i in range(len(packets)):
        if i > 0 and packets[i].haslayer("UDP"):
            if lastindex is not None:
                delay = float(packets[i].time - packets[lastindex].time)
                if delay >= 0.015:
                    time.sleep(delay)

            # Check and modify destination IP for UDP packets
            pkt = packets[i]
            if IP in pkt:
                pkt[IP].dst = "127.0.0.1" 
                del pkt[IP].chksum  
                if UDP in pkt:
                    del pkt[UDP].chksum 

            # Ensure the packet is wrapped in Ethernet if not already
            if Ether not in pkt:
                pkt = Ether() / pkt

            # print(packets[i].summary())  # Print summary of packet
            sendp(packets[i], iface="Ethernet")
            lastindex = i

if __name__ == "__main__":
    traffic_replay()