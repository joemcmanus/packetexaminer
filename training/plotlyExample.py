from scapy.all import *
from collections import Counter, defaultdict
import plotly

packets = rdpcap("example.pcap")

srcIP=[]
for pkt in packets:
    if IP in pkt:
        try:
            srcIP.append(pkt[IP].src)
        except:
            pass

cnt=Counter()
for ip in srcIP:
    cnt[ip] += 1

xData=[]
yData=[]

for ip, count in cnt.most_common():
    xData.append(ip)
    yData.append(count)

plotly.offline.plot({
    "data":[plotly.graph_objs.Bar(x=xData, y=yData)] })
