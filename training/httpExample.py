from scapy.all import *

packets = rdpcap("example.pcap")

for pkt in packets:
    if IP in pkt:
         if http.HTTPRequest in pkt:
            uri=(pkt[http.HTTPRequest].Path).decode("utf-8")
            host=(pkt[http.HTTPRequest].Host).decode("utf-8")
            print(host+uri)

