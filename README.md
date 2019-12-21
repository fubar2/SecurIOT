# SecurIOT
Security test bed for IOT device information leak and vulnerability scanning

Idea is to enable script kiddies to describe and test IOT devices for vulnerabilities and 
to figure out what data they are leaking if any.

pcap contains code to parse a pcap file and make wordclouds of destinations for each source IP
together with host:port specific destination port wordclouds as part of the fingerprinting process
for a new IOT device. 

For example, to make a decent sized file to analyse,
{{
sudo tcpdump host [IOT IP] -i eth0 -c 10000 -w IOTNAME.pcap
}}

will capture all traffic to and from any device IP address and produce wordclouds showing 
how much goes where.


Destinations:

![example local machine destination wordcloud](images/nuc_TCP_wordcloud_example.pcap.png)

Ports:

![example remote machine destination port wordcloud](images/dns.google_port_53_wordcloud_example.pcap.png)



Because we can.

