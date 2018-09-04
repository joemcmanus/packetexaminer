from scapy.all import *

packets = rdpcap("example.pcap")

for pkt in packets:
    if IP in pkt:
        try:
            print(pkt[IP].src)
        except:
            pass


