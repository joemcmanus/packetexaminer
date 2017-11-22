#!/usr/bin/env python3
# File    : packetexaminer.py
# Author  : Joe McManus josephmc@alumni.cmu.edu
# Version : 0.2  11/22/2017 Joe McManus
# Copyright (C) 2017 Joe McManus

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from collections import Counter, defaultdict
import operator
import argparse
import os
#Hide scapy IPv6 message
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try: 
    from scapy.all import *
except:
    print("ERROR: Sorry, could not import scapy. Try 'pip3 install scapy-python3'.")
    quit()

try: 
    from prettytable import PrettyTable
except:
    print("ERROR: Sorry, could not import prettytable. Try 'pip3 install prettytable'.")
    quit()


parser = argparse.ArgumentParser(description='PCAP File Examiner')
parser.add_argument('file', help="Source PCAP File, i.e. example.pcap", type=str)
parser.add_argument('--flows', help="Display flow summary", action="store_true")
parser.add_argument('--dst', help="Display count of destination IPs", action="store_true")
parser.add_argument('--src', help="Display count of source IPs", action="store_true")
parser.add_argument('--bytes', help="Display source and destination byte counts", action="store_true")
parser.add_argument('--dns', help="Display all DNS Lookups in PCAP", action="store_true")
parser.add_argument('--url', help="Display all ULRs in PCAP", action="store_true")
parser.add_argument('--netmap', help="Display a network Map", action="store_true")
parser.add_argument('--all', help="Display all", action="store_true")
parser.add_argument('--limit', help="Limit results to X", type=int)
args=parser.parse_args()

if args.all:
    args.dst=True
    args.flows=True
    args.bytes=True
    args.dst=True
    args.src=True
    args.dns=True
    args.url=True
    args.netmap=True

if args.url:
    try:
        from scapy_http import http
    except:
        print("""ERROR: Scapy does not have http support, skipping url mining.
        You can try the following: 
            wget https://github.com/invernizzi/scapy-http/archive/master.zip
            unzip master.zip
            cd scapy-http-master
            sudo python3 ./setup.py build install. """)
        args.url=False

if args.netmap:
    try:
        import matplotlib.pyplot as plt
    except:
        print("ERROR: Matplotlib not installed, try pip3 install matplotlib or dnf install python3-matplotlib")
        quit()
    try:
        import networkx as nx
    except:
        print("ERROR: NetworkX not installed, try pip3 install networkx")
        quit()

table= PrettyTable(["Option", "Value"])
table.add_row(["File", args.file])
table.add_row(["Limit", args.limit])
table.add_row(["Bytes", args.bytes])
table.add_row(["Flows", args.flows])
table.add_row(["Dst", args.dst])
table.add_row(["Src", args.src])
table.add_row(["DNS", args.dns])
table.add_row(["URLs", args.url])
table.add_row(["Netmap", args.netmap])
print(table)

if os.path.isfile(args.file):
    print("Reading pcap file")
    pkts = rdpcap(args.file)
else: 
    print("ERROR: Can't open pcap file {}".format(args.file))
    quit()

#Build the base, read the pcap file
srcIP=[]
dstIP=[]
srcdst=[]
i=0
for pkt in pkts:
    if IP in pkt:
        srcIP.append(pkt[IP].src)
        dstIP.append(pkt[IP].dst)
        srcdst.append(pkt[IP].src + ","  + pkt[IP].dst)

def simpleCount(ipList, limit, headerOne, headerTwo, title):
    table= PrettyTable([headerOne, headerTwo])
    cnt = Counter()
    for ip in ipList:
        cnt[ip] += 1
    i=0
    for item, count in cnt.most_common(): 
        table.add_row([item,count])
        if limit:
            if i >= limit:
                break
        i+=1
    print(title)
    print(table)	

def flowCount(ipList, limit):
    table= PrettyTable(["Src", "Dst", "Count"])
    cnt = Counter()
    for ip in ipList:
        cnt[ip] += 1
    i=0
    for item, count in cnt.most_common(): 
        src,dst=item.split(',')
        table.add_row([src, dst, count])
        if limit:
            if i >= limit:
                break
        i+=1

    print("Src IP/Dst IP Counts")
    print(table)	

def byteCount(pkts, srcdst, limit):
    srcdstbytes={}
    table= PrettyTable(["Src", "Dst", "Bytes"])
    for pkt in pkts:
        if IP in pkt:
            srcdst=pkt[IP].src + ","  + pkt[IP].dst
            if srcdst in srcdstbytes:
                newBytes=srcdstbytes[srcdst] + pkt[IP].len
                srcdstbytes[srcdst] = newBytes 
            else:
                srcdstbytes[srcdst] = pkt[IP].len
    i=0
    for srcdst, bytes in sorted(srcdstbytes.items(), key=operator.itemgetter(1), reverse=True):
        src,dst=srcdst.split(',')
        table.add_row([src, dst, bytes])
        if limit:
            if i >= limit:
                break
        i+=1

    print(table)

def dnsCount(pkts, limit, headerOne, headerTwo, title):
    lookups=[]
    for pkt in pkts:
        if IP in pkt:
            if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
                lookup=(pkt.getlayer(DNS).qd.qname).decode("utf-8")
                if "arpa" not in lookup:
                    lookups.append(lookup)
     
    simpleCount(lookups, limit, headerOne, headerTwo, title)

def urlCount(pkts, limit, headerOne, headerTwo, title):
    urls=[]
    for pkt in pkts:
        if IP in pkt:
            if http.HTTPRequest in pkt:
                uri=(pkt[http.HTTPRequest].Path).decode("utf-8")
                host=(pkt[http.HTTPRequest].Host).decode("utf-8")
                urls.append(host+uri)
    simpleCount(urls, limit, headerOne, headerTwo, title)

def netmap(srcdst, limit):
    output=[]
    #Create a unique list
    srcdst = list(set(srcdst))
    i=0
    for pair in srcdst:
        src,dst=pair.split(',')
        output.append((src, dst))
        if limit:
            if i >= limit:
                break
        i+=1

    g = nx.Graph()
    edgeList = output
    g.add_edges_from(edgeList)

    pos = nx.spring_layout(g) 
    
    plt.title("PacketExaminer Network Map")

    nx.draw(g,pos, with_labels=True, node_color='#A0CBE2', width=1,edge_cmap=plt.cm.Blues, label_pos=1)

    plt.show()

if args.src:
    simpleCount(srcIP, args.limit, "Source IP", "Count", "Source IP Occurence")
if args.dst:
    simpleCount(dstIP, args.limit, "Dest IP", "Count", "Dest IP Occurence")
if args.flows:
    flowCount(srcdst, args.limit)
if args.bytes:
    byteCount(pkts, srcdst, args.limit)
if args.dns:
    dnsCount(pkts, args.limit, "DNS Lookup", "Count", "Unique DNS Lookups")
if args.url:
    urlCount(pkts, args.limit, "URL", "Count", "Unique URLs" )
if args.netmap:
    netmap(srcdst, args.limit)

