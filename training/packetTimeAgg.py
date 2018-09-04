#!/usr/bin/env python3
# File    : packetTimeAgg.py
# Author  : Joe McManus josephmc@alumni.cmu.edu
# Version : 0.1  09/04/2018 Joe McManus
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
import plotly
from datetime import datetime
import pandas as pd 

#Read the packets from file
packets = rdpcap('example.pcap')

#Lists to hold packet info
pktBytes=[]
pktTimes=[]


#Read each packet and append to the lists. 
for pkt in packets:
    if IP in pkt: 
        try:
            pktBytes.append(pkt[IP].len)

            #First we need to covert Epoch time to a datetime 
            pktTime=datetime.fromtimestamp(pkt.time)
            #Then convert to a format we like
            pktTimes.append(pktTime.strftime("%Y-%m-%d %H:%M:%S.%f"))

        except:
            pass

#This converts list to series
bytes = pd.Series(pktBytes).astype(int)

#Convert the timestamp list to a pd date_time
times = pd.to_datetime(pd.Series(pktTimes).astype(str),  errors='coerce')

#Create the dataframe 
df  = pd.DataFrame({"Bytes": bytes, "Times":times})

#set the date from a range to an timestamp
df = df.set_index('Times')

#Create a new dataframe of 2 second sums to pass to plotly
df2=df.resample('2S').sum()
print(df2)

#Create the graph
plotly.offline.plot({ 
    "data":[plotly.graph_objs.Scatter(x=df2.index, y=df2['Bytes'])],
    "layout":plotly.graph_objs.Layout(title="Bytes over Time ", 
        xaxis=dict(title="Time"),
        yaxis=dict(title="Bytes"))})
