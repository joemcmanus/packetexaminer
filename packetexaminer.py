#!/usr/bin/env python3
# File    : packetex.py
# Author  : Joe McManus josephmc@alumni.cmu.edu
# Version : 0.1  11/21/2017 Joe McManus
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
parser.add_argument('--all', help="Display all", action="store_true")
parser.add_argument('--limit', help="Limit results to X", type=int)
args=parser.parse_args()

if args.all:
    args.dst=True
    args.flows=True
    args.bytes=True
    args.dst=True
    args.src=True

table= PrettyTable(["Option", "Value"])
table.add_row(["File", args.file])
table.add_row(["Limit", args.limit])
table.add_row(["Bytes", args.bytes])
table.add_row(["Flows", args.flows])
table.add_row(["Dst", args.dst])
table.add_row(["Src", args.src])
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
        i+=1
        #if i % 1000 == 0 :
        #    print("Processed {} packets".format(i))

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


if args.src:
    simpleCount(srcIP, args.limit, "Source IP", "Count", "Source IP Occurence")
if args.dst:
    simpleCount(dstIP, args.limit, "Dest IP", "Count", "Dest IP Occurence")
if args.flows:
    flowCount(srcdst, args.limit)
if args.bytes:
    byteCount(pkts, srcdst, args.limit)

#Top DNS 
#Top HTTP 
#Top Ports
