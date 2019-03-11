#!/usr/bin/env python3
# File    : realtime.py
# Author  : Joe McManus josephmc@alumni.cmu.edu
# Version : 0.1  09/16/2018 Joe McManus
# Copyright (C) 2018 Joe McManus

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

from scapy.all import * 
import matplotlib.pyplot as plt
import argparse
from os import getuid

parser = argparse.ArgumentParser(description='Live Traffic Examiner')
parser.add_argument('interface', help="Network interface to listen on i.e. en0", type=str)
parser.add_argument('--count', help="Capture X packets and exit", type=int)
args=parser.parse_args()

#Check to see if we are root, otherwise Scapy might not be able to listen
if getuid() != 0 :
    print("Warning: Not running as root, packet listening may not work.")
    try:
        print("--Trying to listen on {}".format(args.interface))
        sniff(iface=args.interface,count=1)
        print("--Success!")
    except: 
        print("--Failed!\nError: Unable to sniff packets, try again using sudo.")
        quit()

if args.count:
    print("Capturing {} packets on interface {} ".format(args.count, args.interface))
else: 
    print("Capturing unlimited packets on interface {} \n--Press CTRL-C to exit ".format(args.interface))

#Interactive Mode 
plt.ion()


#Labels
plt.ylabel("Bytes")
plt.xlabel("Count")
plt.title("Real Time Network Traffic")
plt.tight_layout()


#Empty list to hold bytes
yData=[]
i=0

#Listen indefinitely, or until we reach count
while True:
    #Listen for 1 packet
    for pkt in sniff(iface=args.interface,count=1): 
        try:
            if IP in pkt:
                yData.append(pkt[IP].len)
                plt.plot(yData)
                #Pause and draw
                plt.pause(0.1)
                i+=1
                if args.count:
                    if i >= args.count:
                        quit()

        except KeyboardInterrupt:
            print("Captured {} packets on interface {} ".format(i, args.interface))
            quit()
