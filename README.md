# packetexaminer
----
This is a harness to perform PCAP analysis that a security engineer may do during an incident response or when looking at network security. I found myslef using a collection of tools and techniques again and again and thought it would be helpful to create a program that would do this for me. This hopefully automates some routine functions you would do manually.

Questions/Feedback/Feature Requests? Please let me know. 

#Features
----
It currently supports:
 - Counts of IPs
 - Bytes between IPS
 - DNS lookups
 - URL mining
 - Source IP counts
 - Dest IP Counts
 - Port Counts
 - Src/Dst Port Counts
 - Network Maps
 - Really basic file extraction (beta)


#Usage
----

     [joe@fedora26 packetexaminer]$ ./packetexaminer.py --help 
     usage: packetexaminer.py [-h] [--flows] [--dst] [--src] [--dport] [--sport]
                              [--ports] [--portbytes] [--bytes] [--dns] [--url]
                              [--netmap] [--xfiles] [--resolve] [--details]
                              [--graphs] [--all] [--limit LIMIT] [--skipopts]
                              file
     
     PCAP File Examiner
     
     positional arguments:
       file           Source PCAP File, i.e. example.pcap
     
     optional arguments:
       -h, --help     show this help message and exit
       --flows        Display flow summary
       --dst          Display count of destination IPs
       --src          Display count of source IPs
       --dport        Display count of destination ports
       --sport        Display count of source ports
       --ports        Display count of all ports
       --portbytes    Display ports by bytes
       --bytes        Display source and destination byte counts
       --dns          Display all DNS Lookups in PCAP
       --url          Display all ULRs in PCAP
       --netmap       Display a network Map
       --xfiles       Extract files from PCAP
       --resolve      Resolve IPs
       --details      Display aditional details where available
       --graphs       Display graphs where available
       --all          Display all
       --limit LIMIT  Limit results to X
       --skipopts     Don't display the options at runtime



#Examples
----
Show the top 10 DNS queries in the PCAP

    [joe@fedora26 packetexaminer]$ ./packetexaminer.py ../http.pcap --dns --limit 10 
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

Show the top 10 DNS queries with the clients that looked them up:

     [joe@fedora26 packetexaminer]$ ./packetexaminer.py ../multiurl.pcap --dns  --details --limit 10 --skipopts 
     --Reading pcap file
     Unique DNS Lookups
     +--------------------------------------------------------------+-------+----------------------------------------------------+
     |                          DNS Lookup                          | Count |                      Clients                       |
     +--------------------------------------------------------------+-------+----------------------------------------------------+
     |                     cdn.optimizely.com.                      |   4   | ['192.168.1.107', '192.168.1.105', '192.168.1.19'] |
     |                    www.summerhamster.com.                    |   3   | ['192.168.1.107', '192.168.1.105', '192.168.1.19'] |
     |                    social-login.cnn.com.                     |   3   | ['192.168.1.107', '192.168.1.105', '192.168.1.19'] |
     |                       w.usabilla.com.                        |   3   | ['192.168.1.107', '192.168.1.105', '192.168.1.19'] |
     |                a125375509.cdn.optimizely.com.                |   3   | ['192.168.1.107', '192.168.1.105', '192.168.1.19'] |
     |                 secure-us.imrworldwide.com.                  |   3   | ['192.168.1.107', '192.168.1.105', '192.168.1.19'] |
     |                         mms.cnn.com.                         |   3   | ['192.168.1.107', '192.168.1.105', '192.168.1.19'] |
     |                    global-ssl.fastly.net.                    |   3   |         ['192.168.1.105', '192.168.1.19']          |
     | ttd-uswest-match-adsrvr-org-454816348.us-west-1.elb.amazonaw |   3   |         ['192.168.1.105', '192.168.1.19']          |
     |                            s.com.                            |       |                                                    |
     |                   aax.amazon-adsystem.com.                   |   2   |         ['192.168.1.107', '192.168.1.19']          |
     |                        data.cnn.com.                         |   2   |         ['192.168.1.107', '192.168.1.19']          |
     +--------------------------------------------------------------+-------+----------------------------------------------------+


Create a network map from the PCAP file.

     [joe@fedora26 packetexaminer]$ ./packetexaminer.py ../http.pcap --limit 50 --netmap 
     +--------+--------------+
     | Option |    Value     |
     +--------+--------------+
     |  File  | ../http.pcap |
     | Limit  |      50      |
     | Bytes  |    False     |
     | Flows  |    False     |
     |  Dst   |    False     |
     |  Src   |    False     |
     |  DNS   |    False     |
     |  URLs  |    False     |
     | Netmap |     True     |
     +--------+--------------+
     Reading pcap file

![alt_tag](https://github.com/joemcmanus/packetexaminer/blob/master/img/netmap.jpg)

Graphs can be created by passing the --graphs option 

![alt_tag](https://github.com/joemcmanus/packetexaminer/blob/master/img/dnsGraph.png)
![alt_tag](https://github.com/joemcmanus/packetexaminer/blob/master/img/byteGraph.png)
![alt_tag](https://github.com/joemcmanus/packetexaminer/blob/master/img/srcGraph.png)

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


Show the top 5 URLs and the clients who accessed them. 

     [joe@fedora26 packetexaminer]$ ./packetexaminer.py ../multiurl.pcap --url  --details --limit 5 
     +--------------+------------------+
     |    Option    |      Value       |
     +--------------+------------------+
     |     File     | ../multiurl.pcap |
     |    Limit     |        5         |
     |    Bytes     |      False       |
     |    Flows     |      False       |
     |     Dst      |      False       |
     |     Src      |      False       |
     |     DNS      |      False       |
     |     URLs     |       True       |
     |    Netmap    |      False       |
     | Xtract Files |      False       |
     | Resolve IPs  |      False       |
     |   Details    |       True       |
     +--------------+------------------+
     --Reading pcap file
     Unique URLs
     +--------------------------------------------------------------+-------+----------------------------------------------------+
     |                             URL                              | Count |                      Clients                       |
     +--------------------------------------------------------------+-------+----------------------------------------------------+
     |              cdn.optimizely.com/js/131788053.js              |   3   | ['192.168.1.107', '192.168.1.105', '192.168.1.19'] |
     | mab.chartbeat.com/mab_strategy/headline_testing/get_strategy |   3   | ['192.168.1.107', '192.168.1.105', '192.168.1.19'] |
     |            /?host=cnn.com&domain=cnn.com&path=%2F            |       |                                                    |
     | data.cnn.com/jsonp/breaking_news/domestic.json?callback=CNNB |   3   | ['192.168.1.107', '192.168.1.105', '192.168.1.19'] |
     |                     reakingNewsCallback                      |       |                                                    |
     | beacon.krxd.net/optout_check?callback=Krux.ns._default.kxjso |   3   | ['192.168.1.107', '192.168.1.105', '192.168.1.19'] |
     |                        np_optOutCheck                        |       |                                                    |
     | s.amazon-adsystem.com/iu3?cm3ppd=1&d=dtb-pub&csif=t&dl=ox_an |   3   |         ['192.168.1.105', '192.168.1.19']          |
     |             c.amazon-adsystem.com/aax2/apstag.js             |   2   |         ['192.168.1.105', '192.168.1.19']          |
     | native.sharethrough.com/assets/sfp-creative-hub-listener.js  |   2   |         ['192.168.1.105', '192.168.1.19']          |
     |             w.usabilla.com/0649ef72a7be.js?lv=1              |   2   |         ['192.168.1.105', '192.168.1.19']          |
     | us-u.openx.net/w/1.0/cm?id=e818ca1e-0c23-caa8-0dd3-096b0ada0 |   2   |                 ['192.168.1.105']                  |
     | 8b7&ph=2d1251ae-7f3a-47cf-bd2a-2f288854a0ba&plm=5&r=http%3A% |       |                                                    |
     |  2F%2Fs.amazon-adsystem.com%2Fecm3%3Fex%3Dopenx.com%26id%3D  |       |                                                    |
     | fastlane.rubiconproject.com/a/api/fastlane.json?account_id=1 |   2   |                 ['192.168.1.105']                  |
     | 1078&size_id=15&p_pos=btf&rp_floor=0.01&rf=http%3A%2F%2Fwww. |       |                                                    |
     | cnn.com%2Fvideos%2Fpolitics%2F2017%2F12%2F04%2Fspeier-reacti |       |                                                    |
     | on-manafort-bail-deal-sot-tsr.cnn&p_screen_res=768x1024&tg_f |       |                                                    |
     | l.eid=ad_rect_btf_01&tid=d4587982-0a3f-482a-9c60-4e7905ab7cb |       |                                                    |
     | 7&tg_fl.uname=%2F8664377%2FCNN%2Fpolitics%2Fvideo&tg_fl.pr_a |       |                                                    |
     | cctid=11078&kw=CNN%2Fpolitics%2Fvideo%2Crp.fastlane&tk_flint |       |                                                    |
     | =plain&tg_i.site=CNN&tg_i.section=politics&tg_i.subsection=v |       |                                                    |
     | ideo&tg_i.cap_topics=350%2C7WN%2C3QV%2CH2%2CC45Z%2CBPP%2CDHX |       |                                                    |
     | %2CJBH%2C13YM%2C7JY%2C5G0%2CF68%2C5FT%2C6GK%2C7XK%2C5B3%2C6G |       |                                                    |
     | L%2CDG2%2CDF7%2C7WP%2C6HF&tg_i.ssl=0&tg_i.pos=rect_btf_01&ra |       |                                                    |
     |                    nd=0.6629693918205324                     |       |                                                    |
     | googleads.g.doubleclick.net/pagead/viewthroughconversion/986 |   2   |         ['192.168.1.105', '192.168.1.19']          |
     |               255830/?value=0&guid=ON&script=0               |       |                                                    |
     +--------------------------------------------------------------+-------+----------------------------------------------------+


Show the top 10 hosts in the PCAP by bytes and reolve the IP.

     [joe@fedora26 packetexaminer]$ ./packetexaminer.py --bytes --resolve --limit 10 ../http.pcap 
     +--------------+--------------+
     |    Option    |    Value     |
     +--------------+--------------+
     |     File     | ../http.pcap |
     |    Limit     |      10      |
     |    Bytes     |     True     |
     |    Flows     |    False     |
     |     Dst      |    False     |
     |     Src      |    False     |
     |     DNS      |    False     |
     |     URLs     |    False     |
     |    Netmap    |    False     |
     | Xtract Files |    False     |
     | Resolve IPs  |     True     |
     +--------------+--------------+
     --Reading pcap file
     +------------------------------------------------------+------------------------------------------------------+--------+
     |                         Src                          |                         Dst                          | Bytes  |
     +------------------------------------------------------+------------------------------------------------------+--------+
     |                    151.101.65.67                     |                    192.168.1.107                     | 900959 |
     |      server-54-230-5-161.dfw3.r.cloudfront.net       |                    192.168.1.107                     | 852131 |
     | a23-217-102-176.deploy.static.akamaitechnologies.com |                    192.168.1.107                     | 851062 |
     |               den02s01-in-f4.1e100.net               |                    192.168.1.107                     | 316173 |
     | a23-217-104-212.deploy.static.akamaitechnologies.com |                    192.168.1.107                     | 225254 |
     |      server-54-230-7-190.dfw3.r.cloudfront.net       |                    192.168.1.107                     | 183203 |
     |                     slashdot.org                     |                    192.168.1.107                     | 166102 |
     | a23-217-102-181.deploy.static.akamaitechnologies.com |                    192.168.1.107                     | 152499 |
     |                    192.168.1.107                     | a23-217-102-176.deploy.static.akamaitechnologies.com | 141654 |
     |                    151.101.64.175                    |                    192.168.1.107                     | 124329 |
     | a23-217-103-184.deploy.static.akamaitechnologies.com |                    192.168.1.107                     | 115715 |
     +------------------------------------------------------+------------------------------------------------------+--------+

