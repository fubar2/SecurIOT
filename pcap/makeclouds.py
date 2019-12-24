from scapy.all import *
from wordcloud import WordCloud
from collections import Counter
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
import socket
import os
from random import randint


# parse a pcap file and produce wordclouds for each IP destination packets
# for stats also can use tshark on pcap - eg:
# tshark -q -z hosts -z dns,tree -z bootp,stat -z conv,tcp -z conv,udp -z conv,ip -z endpoints,udp -z io,phs -r xiaofang_setupandtest.gz.pcap.gz > foo


# infname = '/home/ross/rossgit/pcap/eg2.pcap'
# infname = '/home/ross/rossgit/pcap/example.pcap'
# infname = "/home/ross/rossgit/pcap/tplinkHS100.gz.pcap.gz"
infname = "/home/ross/rossgit/pcap/xiaofang_setupandtest.gz.pcap.gz"
pnames = ['IP','TCP','ARP','UDP','ICMP']
pobj = [IP,TCP,ARP,UDP,ICMP]

doGraphs = True # these are same as wordclouds for each ip and too big for all ip/port to make any sense AFAIK

if doGraphs: 
	# network graph construction and plotting is relatively easy but 
	# not useful for single sources and too messy if all IP.
	import networkx as nx
	gIP = nx.Graph()
	gPORT = nx.Graph()

def random_color_func(word=None, font_size=None, position=None,  orientation=None, font_path=None, random_state=None):
	"""https://stackoverflow.com/questions/43043263/word-cloud-in-python-with-customised-colour"""
	h = int(360.0 * 21.0 / 255.0) # orange base
	s = int(100.0 * 255.0 / 255.0)
	l = int(100.0 * float(randint(60, 120)) / 255.0)

	return "hsl({}, {}%, {}%)".format(h, s, l)

def getsrcdest(pkt,proto):
	"""need from every packet of interest"""
	saucen = None
	destn = None
	dport = None
	sport = None
	if IP in pkt:
		saucen = pkt[IP].src
		destn = pkt[IP].dst
	if (TCP in pkt):
		sport = pkt[TCP].sport
		dport = pkt[TCP].dport
	elif UDP in pkt:
		sport = pkt[UDP].sport
		dport = pkt[UDP].dport
		
	return (saucen,destn,str(sport),str(dport))   

def lookup(sauce,sourcen,deens):
	"""deens caches all slow! fqdn reverse dns lookups from ip"""
	kname = deens.get(sourcen)
	if kname == None:
		kname = socket.getfqdn(sourcen) # PIA dns is slow!!
		deens[sourcen] = kname
	newsaucen = kname
	sk = sauce.keys()
	newsauce = {}
	for k in sk:
		kname = deens.get(k,None)
		if kname == None:
			kname = socket.getfqdn(k)
			deens[k] = kname
		newsauce[kname] = sauce[k]
	return (newsauce,newsaucen)

def readPcap(infile,seenIP,seenPORT):
	"""single pass version """
	allIP = set()
	allPORT = set()
	for i,proto in enumerate(pobj):
			pn = pnames[i]
			seenIP[pn] = {}
	for pkt in PcapReader(infile):
		for i,proto in enumerate(pobj):
			pn = pnames[i]
			if proto in pkt:
				nsauce,ndest,sport,dport = getsrcdest(pkt,proto)
				bingo = False
				ipport = '%s_%s' % (nsauce,sport)
				if seenPORT.get(ipport,None) == None:
					c = Counter()
					seenPORT[ipport] = c
					seenPORT[ipport][dport] = 1
					allPORT.add(ipport)
					bingo = True
				else:
					seenPORT[ipport][dport] += 1
					bingo = True
				if seenIP[pn].get(nsauce,None):
					seenIP[pn][nsauce][ndest] += 1
					bingo = True
				else:
					c = Counter()
					seenIP[pn][nsauce] = c
					seenIP[pn][nsauce][ndest] = 1
					allIP.add(nsauce)
					allIP.add(ndest)
					bingo = True
				if bingo:
					continue
	return(seenIP,seenPORT,allIP,allPORT)

		  
def processPcap(seenIP,seenPORT,deens):
	pics = []
	for i,proto in enumerate(pobj):
		pn = pnames[i]
		for nsauce in seenIP[pn].keys():
			k = seenIP[pn][nsauce].keys()
			kl = len(k)
			if kl > 1:
				sf,newsaucen = lookup(seenIP[pn][nsauce],nsauce,deens) # expensive operation so moved here
				if doGraphs:
					nody = list(sf.keys())
					nody.append(newsaucen)
					gIP.add_nodes_from(nody)
					edgy = [(newsaucen,x,{'weight':sf[x]}) for x in sf]
					gIP.add_edges_from(edgy)
				outfn = '%s_%s_wordcloud_%s.png' % (newsaucen,pn,os.path.basename(infname))
				wc = WordCloud(background_color="white",width=1200, height=1000,max_words=200,
				 min_font_size=20,
				color_func=random_color_func).generate_from_frequencies(sf)
				f = plt.figure(figsize=(10, 10))
				plt.imshow(wc, interpolation='bilinear')
				plt.axis('off')
				plt.title('%s %s destination word cloud' % (nsauce,pn))
				# plt.show()
				f.savefig(outfn, bbox_inches='tight')
				plt.clf() 
				pics.append(outfn)

	for sport in seenPORT.keys():
		k = seenPORT[sport].keys()
		kl = len(k)
		sf = seenPORT[sport]
		s,p = sport.split('_')
		sname = deens.get(s,s)
		snameport = '%s_port_%s' % (sname,p)
		if kl > 5:
			if doGraphs:
				gPORT.add_nodes_from(k)
				pawts = [(snameport,x,{'weight':seenPORT[sport][x]}) for x in k]
				gPORT.add_edges_from(pawts)
			outfn = '%s_wordcloud_%s.png' % (snameport,os.path.basename(infname))
			wc = WordCloud(background_color="white",width=1200, height=1000,
				max_words=200,min_font_size=10,
				color_func=random_color_func).generate_from_frequencies(sf)
			f = plt.figure(figsize=(10, 10))
			plt.imshow(wc, interpolation='bilinear')
			plt.axis('off')
			plt.title('%s destination port word cloud' % (snameport))
			# plt.show()
			f.savefig(outfn, bbox_inches='tight')
			plt.clf() 
			pics.append(outfn)
	return(deens,pics)

def writeIndex(pics):
	"""make a simple html page to view report
	"""
	outfn = '%s_wordcloud.html' % (os.path.basename(infname))
	h = ["""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
</head><body>
<h1>Crude example %s Makeclouds report</h1>\n<table border="1">""" % os.path.basename(infname),]
	for p in pics:
		if p.endswith('txt'):
			t = open(p,'r').readlines()
			s = "<tr><td><a href='%s'>tshark %s report</a><br><pre style='white-space: pre-wrap;'>%s</pre></td></tr>" %\
				(p,p.split('_')[0],''.join(t[1:-1])) 
			# ignore === lines at start and end
		else:
			s = "<tr><td><img src='%s' alt='%s'></td></tr>" % (p,p)
		h.append(s)
	h.append("</table></body></html>")
	f = open('makeclouds.html','w')
	f.write('\n'.join(h))
	f.close()

def doTshark():
	"""grab and process - sample part - fugly - some have table headers
	cl = "tshark -q -z hosts -z dns,tree -z bootp,stat -z conv,tcp -z conv,udp -z conv,ip -z endpoints,udp -z io,phs -r %s" % (infname)
	
	===================================================================
Protocol Hierarchy Statistics
Filter:

eth                                      frames:2379 bytes:1340216
  ip                                     frames:2327 bytes:1336746
	udp                                  frames:2157 bytes:1284526
	  ssdp                               frames:16 bytes:3328
	  mdns                               frames:9 bytes:1923
	  bootp                              frames:9 bytes:3078
	  dns                                frames:14 bytes:1400
	  ntp                                frames:4 bytes:360
	  data                               frames:2105 bytes:1274437
	tcp                                  frames:165 bytes:51718
	  ssl                                frames:43 bytes:19288
		tcp.segments                     frames:5 bytes:3850
	  _ws.malformed                      frames:10 bytes:10920
	icmp                                 frames:5 bytes:502
  ipv6                                   frames:15 bytes:1505
	udp                                  frames:3 bytes:609
	  mdns                               frames:3 bytes:609
	icmpv6                               frames:12 bytes:896
  arp                                    frames:31 bytes:1302
  llc                                    frames:1 bytes:20
	basicxid                             frames:1 bytes:20
  eapol                                  frames:5 bytes:643
===================================================================

	
	"""
	rclist = ["-z hosts","-z dns,tree", "-z bootp,stat", "-z conv,tcp", "-z conv,udp", "-z conv,ip", "-z endpoints,udp", "-z io,phs","-P"]
	rfnames = ['hosts','dns','dhcp','tcpconv','udpconv','ipconv','udpendpoints','iophs','pdump']
	for i,com in enumerate(rclist):
		ofn = "%s_%s.txt" % (rfnames[i],os.path.basename(infname))
		cl = "tshark -q %s -r %s > %s" % (com,infname,ofn)
		os.system(cl)
		pics.append(ofn)

if __name__=="__main__":
	seenIP,seenPORT,allIP,allPORT = readPcap(infname,{},{})
	deens,pics = processPcap(seenIP,seenPORT,{})
	writeIndex(pics)
	doTshark()
	if doGraphs:
		f = plt.figure(figsize=(10, 10))
		arc_weight = nx.get_edge_attributes(gIP,'weight')
		edges,weights = zip(*nx.get_edge_attributes(gIP,'weight').items())
		ws = sum(weights)
		weights = [float(x)/ws for x in weights] 
		node_pos=nx.spring_layout(gIP) 
		nx.draw_networkx(gIP, node_pos,node_size=450,node_color='y')
		#nx.draw(gIP, with_labels=False, font_weight='bold')
		nx.draw_networkx_edges(gIP, node_pos,  edge_color=weights)
		nx.draw_networkx_edge_labels(gIP, node_pos, edge_labels=arc_weight)
		outfn = '%s_ipnet.jpg' % os.path.basename(infname)
		plt.title('Network of traffic between IP addresses in %s' % os.path.basename(infname))
		plt.savefig(outfn)
		pics.append(outfn)
		plt.clf() 
		arc_weight = nx.get_edge_attributes(gPORT,'weight')
		node_pos=nx.spring_layout(gPORT) 
		nx.draw_networkx(gPORT, node_pos,node_size=450,node_color='y')
		nx.draw_networkx_edges(gPORT, node_pos)
		nx.draw_networkx_edge_labels(gPORT, node_pos, edge_labels=arc_weight)
		outfn = '%s_portnet.jpg' % os.path.basename(infname)
		plt.title('Network of traffic between port numbers in %s' % os.path.basename(infname))
		plt.savefig(outfn)
		pics.append(outfn)
	writeIndex(pics)

