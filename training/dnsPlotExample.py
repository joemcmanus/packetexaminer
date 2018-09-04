from scapy.all import *
from collections import Counter, defaultdict
import plotly

packets = rdpcap("example.pcap")

lookups=[]
for pkt in packets:
    if IP in pkt:
        try:
            if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
                lookup=(pkt.getlayer(DNS).qd.qname).decode("utf-8")
                lookups.append(lookup)
        except:
            pass

cnt=Counter()
for lookup in lookups:
    cnt[lookup] += 1

xData=[]
yData=[]

for lookup, count in cnt.most_common():
    xData.append(lookup)
    yData.append(count)

plotly.offline.plot({
    "data":[plotly.graph_objs.Bar(x=xData, y=yData)] })
