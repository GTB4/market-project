from scapy.all import sniff, Raw
from scapy.layers.inet import IP

def ip_monitor_callback(pkt):
    if IP in pkt: 
        #print()
        target_bytes = bytes([0x49, 0x74, 0x65, 0x6d, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x54, 0x79, 0x70, 0x65, 0x49, 0x64]) #mean ItemGroupTypeId
        # print(pkt[IP])
        if pkt[IP].src == "5.188.125.28" and target_bytes in pkt[Raw].load:
            #print("Packet sniffed: ", pkt.show()) 
            #print("Packet receved: ",pkt[Raw].load) # To get readeble data
            print("Raw Packet receved: ", repr(pkt[Raw].load)) #To get raw data

#def arp_monitor_callback():
def sniff_packets():
    print("I am sniffing")
    #sniff(prn=arp_monitor_callback, filter="arp", store=0)  
    sniff(prn=ip_monitor_callback, filter="ip", store=0)  

if __name__ == "__main__":
    sniff_packets()