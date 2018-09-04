from scapy.all import *
from scapy_http import http

packets = rdpcap("example.pcap")

for pkt in packets:
    if IP in pkt:
         if http.HTTPRequest in pkt:
            uri=(pkt[http.HTTPRequest].Path).decode("utf-8")
            host=(pkt[http.HTTPRequest].Host).decode("utf-8")
            print(host+uri)

