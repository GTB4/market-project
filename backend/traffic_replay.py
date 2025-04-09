from scapy.all import rdpcap, sendp, conf, get_if_list
import time

def traffic_replay():
    #this is a test
    conf.iface = get_if_list()[0]
    print(conf.iface)
    #end of test

    print("I replay")
    packets = rdpcap(r"C:\Users\GTB4\Documents\WireShark_data\leather_armor_t6.pcap")


    for i in range(len(packets)):
        if i > 0:
            delay = float(packets[i].time - packets[i - 1].time)
            time.sleep(delay)
        sendp(packets[i], iface="\\Device\\NPF_Loopback")

if __name__ == "__main__":
    traffic_replay()