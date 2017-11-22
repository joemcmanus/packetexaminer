# packetexaminer
----
This is a somple harness to do PCAP analysis. This hopefully automates a lot of the function an analyst would do manually. 

Coming in the next day or two is visualization using NetworkX

#Features
----
It currently supports:
 - Counts of IPs
 - Bytes between IPS
 - DNS lookups
 - URLs


#Usage
----
    [joe@fedora26 packetexaminer]$ ./packetexaminer.py --help 
     usage: packetexaminer.py [-h] [--flows] [--dst] [--src] [--bytes] [--dns]
                              [--url] [--all] [--limit LIMIT]
                              file
     
     PCAP File Examiner
     
     positional arguments:
       file           Source PCAP File, i.e. example.pcap
     
     optional arguments:
       -h, --help     show this help message and exit
       --flows        Display flow summary
       --dst          Display count of destination IPs
       --src          Display count of source IPs
       --bytes        Display source and destination byte counts
       --dns          Display all DNS Lookups in PCAP
       --url          Display all ULRs in PCAP
       --all          Display all
       --limit LIMIT  Limit results to X


#Examples
----
Show to top 10 DNS queries in the PCAP

    [joe@fedora26 packetexaminer]$ ./packetexaminer.py ../http.pcap --dns --limit 10 
     +--------+--------------+
     | Option |    Value     |
     +--------+--------------+
     |  File  | ../http.pcap |
     | Limit  |      10      |
     | Bytes  |    False     |
     | Flows  |    False     |
     |  Dst   |    False     |
     |  Src   |    False     |
     |  DNS   |     True     |
     |  URLs  |    False     |
     +--------+--------------+
     Reading pcap file
     Unique DNS Lookups
     +----------------------------------+-------+
     |            DNS Lookup            | Count |
     +----------------------------------+-------+
     |          bat.bing.com.           |   3   |
     |     tag.bounceexchange.com.      |   3   |
     |      amplify.outbrain.com.       |   3   |
     |         t.tellapart.com.         |   3   |
     |   fastlane.rubiconproject.com.   |   2   |
     | optimized-by.rubiconproject.com. |   2   |
     |  pagead2.googlesyndication.com.  |   2   |
     |       logx.optimizely.com.       |   2   |
     |      static.chartbeat.com.       |   2   |
     |        static.criteo.net.        |   2   |
     |  a125375509.cdn.optimizely.com.  |   2   |
     +----------------------------------+-------+


Show to the 10 SRC/DST Flows

     [joe@fedora26 packetexaminer]$ ./packetexaminer.py ../http.pcap --flows --limit 10 
     +--------+--------------+
     | Option |    Value     |
     +--------+--------------+
     |  File  | ../http.pcap |
     | Limit  |      10      |
     | Bytes  |    False     |
     | Flows  |     True     |
     |  Dst   |    False     |
     |  Src   |    False     |
     |  DNS   |    False     |
     |  URLs  |    False     |
     +--------+--------------+
     Reading pcap file
     Src IP/Dst IP Counts
     +----------------+----------------+-------+
     |      Src       |      Dst       | Count |
     +----------------+----------------+-------+
     | 151.101.65.67  | 192.168.1.107  |  687  |
     | 23.217.102.176 | 192.168.1.107  |  673  |
     | 192.168.1.107  | 151.101.65.67  |  615  |
     |  54.230.5.161  | 192.168.1.107  |  584  |
     | 192.168.1.107  | 23.217.102.176 |  554  |
     | 172.217.11.228 | 192.168.1.107  |  495  |
     | 192.168.1.107  |  54.230.5.161  |  478  |
     | 192.168.1.107  | 172.217.11.228 |  370  |
     | 23.217.104.212 | 192.168.1.107  |  204  |
     | 216.34.181.45  | 192.168.1.107  |  194  |
     | 192.168.1.107  | 23.217.104.212 |  185  |
     +----------------+----------------+-------+

Show to top 10 SRC/DST by bytes

     [joe@fedora26 packetexaminer]$ ./packetexaminer.py ../http.pcap --bytes --limit 10 
     +--------+--------------+
     | Option |    Value     |
     +--------+--------------+
     |  File  | ../http.pcap |
     | Limit  |      10      |
     | Bytes  |     True     |
     | Flows  |    False     |
     |  Dst   |    False     |
     |  Src   |    False     |
     |  DNS   |    False     |
     |  URLs  |    False     |
     +--------+--------------+
     Reading pcap file
     +----------------+----------------+--------+
     |      Src       |      Dst       | Bytes  |
     +----------------+----------------+--------+
     | 151.101.65.67  | 192.168.1.107  | 900959 |
     |  54.230.5.161  | 192.168.1.107  | 852131 |
     | 23.217.102.176 | 192.168.1.107  | 851062 |
     | 172.217.11.228 | 192.168.1.107  | 316173 |
     | 23.217.104.212 | 192.168.1.107  | 225254 |
     |  54.230.7.190  | 192.168.1.107  | 183203 |
     | 216.34.181.45  | 192.168.1.107  | 166102 |
     | 23.217.102.181 | 192.168.1.107  | 152499 |
     | 192.168.1.107  | 23.217.102.176 | 141654 |
     | 151.101.64.175 | 192.168.1.107  | 124329 |
     | 23.217.103.184 | 192.168.1.107  | 115715 |
     +----------------+----------------+--------+

Show the top 10 URLs in the pcap. 

     [joe@fedora26 packetexaminer]$ ./packetexaminer.py ../http.pcap --url --limit 10 
     +--------+--------------+
     | Option |    Value     |
     +--------+--------------+
     |  File  | ../http.pcap |
     | Limit  |      10      |
     | Bytes  |    False     |
     | Flows  |    False     |
     |  Dst   |    False     |
     |  Src   |    False     |
     |  DNS   |    False     |
     |  URLs  |     True     |
     +--------+--------------+
     Reading pcap file
     Unique URLs
     +------------------------------------------------------------+-------+
     |                            URL                             | Count |
     +------------------------------------------------------------+-------+
     |          static.chartbeat.com/js/chartbeat_mab.js          |   4   |
     |          www.googletagservices.com/tag/js/gpt.js           |   4   |
     |       cdn.cnn.com/ads/cnn/singles/cnn_homepage_rb.js       |   4   |
     |               cdn3.optimizely.com/js/geo2.js               |   4   |
     |            cdn.krxd.net/controltag/ITb_4eqO.js             |   4   |
     |         cdn.cnn.com/analytics/cnnexpan/jsmd.min.js         |   3   |
     |    www.i.cdn.cnn.com/.a/2.49.5/js/cnn-footer-lib.min.js    |   3   |
     |    www.i.cdn.cnn.com/.a/2.49.5/js/cnn-analytics.min.js     |   3   |
     |   cdn.cnn.com/cnn/.e1mo/img/4.0/logos/menu_politics.png    |   3   |
     |     cdn.cnn.com/cnn/.e1mo/img/4.0/logos/menu_money.png     |   3   |
     | cdn.cnn.com/cnn/.e1mo/img/4.0/logos/menu_entertainment.png |   3   |
     +------------------------------------------------------------+-------+

