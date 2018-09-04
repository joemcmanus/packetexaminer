from scapy.all import *

packets = rdpcap("example.pcap")

for pkt in packets:
    if IP in pkt:
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
            lookup=(pkt.getlayer(DNS).qd.qname).decode("utf-8")
            print(lookup)

