from scapy.all import *
from wordcloud import WordCloud
from collections import Counter
import matplotlib
from matplotlib import cm
from matplotlib.colors import ListedColormap, LinearSegmentedColormap

matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
import socket
import os
from random import randint

# geoip stuff
# ross@nuc:~/rossgit/PcapViz$ python3
# Python 3.7.5 (default, Nov  7 2019, 10:50:52)
# [GCC 8.3.0] on linux
# Type "help", "copyright", "credits" or "license" for more information.
# >>> import maxminddb
# >>> reader = maxminddb.open_database('/usr/share/GeoIP/GeoLite2-City.mmdb')
# >>> reader.get('137.59.252.179')
# {'city': {'geoname_id': 2147714, 'names': {'de': 'Sydney', 'en': 'Sydney', 'es': 'Sídney', 'fr': 'Sydney', 'ja': 'シドニー', 'pt-BR': 'Sydney', 'ru': 'Сидней', 'zh-CN': '悉尼'}},
# 'continent': {'code': 'OC', 'geoname_id': 6255151, 
# 'names': {'de': 'Ozeanien', 'en': 'Oceania', 'es': 'Oceanía', 'fr': 'Océanie', 'ja': 'オセアニア', 'pt-BR': 'Oceania', 'ru': 'Океания', 'zh-CN': '大洋洲'}}, 
# 'country': {'geoname_id': 2077456, 'iso_code': 'AU', 'names': {'de': 'Australien', 'en': 'Australia',
# 'es': 'Australia', 'fr': 'Australie', 'ja': 'オーストラリア', 'pt-BR': 'Austrália', 'ru': 'Австралия', 'zh-CN': '澳大利亚'}},
# 'location': {'accuracy_radius': 500, 'latitude': -33.8591, 'longitude': 151.2002, 'time_zone': 'Australia/Sydney'}, 'postal': {'code': '2000'}, 
# 'registered_country': {'geoname_id': 1861060, 'iso_code': 'JP', 'names': {'de': 'Japan', 'en': 'Japan', 'es': 'Japón', 'fr': 'Japon', 'ja': '日本', 'pt-BR': 'Japão', 'ru': 'Япония', 'zh-CN': '日本'}}, 
# 'subdivisions': [{'geoname_id': 2155400, 'iso_code': 'NSW', 'names': {'en': 'New South Wales', 'fr': 'Nouvelle-Galles du Sud', 'pt-BR': 'Nova Gales do Sul', 
# 'ru': 'Новый Южный Уэльс'}}]}
# >>> 

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
					nody = sf.keys()
					#nody.append(newsaucen)
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
	outfn = '%s_report.html' % (os.path.basename(infname))
	h = ["""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
</head><body>
<h1>Crude example %s Makeclouds report</h1>\n<table border="1">""" % os.path.basename(infname),]
	for p in pics:
		if p.endswith('txt'):
			t = open(p,'r').readlines()
			reprt = ''.join(t[1:-1])  # ignore === lines at start and end
			s = "<tr><td><a href='%s'>tshark %s report</a><br><pre style='white-space: pre-wrap;'>%s</pre></td></tr>" %\
				(p,p.split('_')[0],reprt)
		else:
			s = "<tr><td><img src='%s' alt='%s'></td></tr>" % (p,p)
		h.append(s)
	h.append("</table></body></html>")
	f = open(outfn,'w')
	f.write('\n'.join(h))
	f.close()

def doTshark():
	"""grab and process - sample part - fugly - some have table headers
	cl = "tshark -q -z hosts -z dns,tree -z bootp,stat -z conv,tcp -z conv,udp -z conv,ip -z endpoints,udp -z io,phs -r %s" % (infname)	
	tshark: Invalid -z argument "credentials"; it must be one of:
     afp,srt
     ancp,tree
     ansi_a,bsmap
     ansi_a,dtap
     ansi_map
     bacapp_instanceid,tree
     bacapp_ip,tree
     bacapp_objectid,tree
     bacapp_service,tree
     camel,counter
     camel,srt
     collectd,tree
     conv,bluetooth
     conv,eth
     conv,fc
     conv,fddi
     conv,ip
     conv,ipv6
     conv,ipx
     conv,jxta
     conv,mptcp
     conv,ncp
     conv,rsvp
     conv,sctp
     conv,sll
     conv,tcp
     conv,tr
     conv,udp
     conv,usb
     conv,wlan
     dcerpc,srt
     dests,tree
     dhcp,stat
     diameter,avp
     diameter,srt
     dns,tree
     endpoints,bluetooth
     endpoints,eth
     endpoints,fc
     endpoints,fddi
     endpoints,ip
     endpoints,ipv6
     endpoints,ipx
     endpoints,jxta
     endpoints,mptcp
     endpoints,ncp
     endpoints,rsvp
     endpoints,sctp
     endpoints,sll
     endpoints,tcp
     endpoints,tr
     endpoints,udp
     endpoints,usb
     endpoints,wlan
     expert
     f5_tmm_dist,tree
     f5_virt_dist,tree
     fc,srt
     flow,any
     flow,icmp
     flow,icmpv6
     flow,lbm_uim
     flow,tcp
     follow,http
     follow,tcp
     follow,tls
     follow,udp
     gsm_a
     gsm_a,bssmap
     gsm_a,dtap_cc
     gsm_a,dtap_gmm
     gsm_a,dtap_mm
     gsm_a,dtap_rr
     gsm_a,dtap_sacch
     gsm_a,dtap_sm
     gsm_a,dtap_sms
     gsm_a,dtap_ss
     gsm_a,dtap_tp
     gsm_map,operation
     gtp,srt
     h225,counter
     h225_ras,rtd
     hart_ip,tree
     hosts
     hpfeeds,tree
     http,stat
     http,tree
     http2,tree
     http_req,tree
     http_seq,tree
     http_srv,tree
     icmp,srt
     icmpv6,srt
     io,phs
     io,stat
     ip_hosts,tree
     ip_srcdst,tree
     ipv6_dests,tree
     ipv6_hosts,tree
     ipv6_ptype,tree
     ipv6_srcdst,tree
     isup_msg,tree
     lbmr_queue_ads_queue,tree
     lbmr_queue_ads_source,tree
     lbmr_queue_queries_queue,tree
     lbmr_queue_queries_receiver,tree
     lbmr_topic_ads_source,tree
     lbmr_topic_ads_topic,tree
     lbmr_topic_ads_transport,tree
     lbmr_topic_queries_pattern,tree
     lbmr_topic_queries_pattern_receiver,tree
     lbmr_topic_queries_receiver,tree
     lbmr_topic_queries_topic,tree
     ldap,srt
     mac-lte,stat
     megaco,rtd
     mgcp,rtd
     mtp3,msus
     ncp,srt
     osmux,tree
     plen,tree
     proto,colinfo
     ptype,tree
     radius,rtd
     rlc-lte,stat
     rpc,programs
     rpc,srt
     rtp,streams
     rtsp,stat
     rtsp,tree
     sametime,tree
     scsi,srt
     sctp,stat
     sip,stat
     smb,sids
     smb,srt
     smb2,srt
     smpp_commands,tree
     sv
     ucp_messages,tree
     wsp,stat

	
	"""
	rclist = ["-z hosts","-z dns,tree", "-z dhcp,stat", "-z conv,tcp", "-z conv,udp", "-z conv,ip", "-z endpoints,udp", "-z io,phs","-z http,tree","-P"]
	rfnames = ['hosts','dns','dhcpstat','tcpconv','udpconv','ipconv','udpendpoints','iophs','httptree','pdump']
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
		viridis = cm.get_cmap('viridis', 12)
		f = plt.figure(figsize=(10, 10))
		n_weight = nx.get_edge_attributes(gIP,'weight') # count
		edges,weights = zip(*nx.get_edge_attributes(gIP,'weight').items())
		ws = sum(weights)
		weights = [float(x)/ws for x in weights] # fractional weights summing to 1
		node_pos=nx.spring_layout(gIP) 
		nx.draw_networkx(gIP, node_pos,node_size=450,node_color='y',edgelist=[])
		nx.draw_networkx_edges(gIP, node_pos,  edge_color=weights,edge_cmap=viridis,edge_style="dashed")
		nx.draw_networkx_edge_labels(gIP, node_pos, edge_labels=n_weight)
		outfn = '%s_ipnet.jpg' % os.path.basename(infname)
		plt.title('Network of traffic between IP addresses in %s' % os.path.basename(infname))
		plt.savefig(outfn)
		pics.append(outfn)
		plt.clf() 
		n_weight = nx.get_edge_attributes(gPORT,'weight')
		edges,weights = zip(*nx.get_edge_attributes(gPORT,'weight').items())
		ws = sum(weights)
		weights = [float(x)/ws for x in weights] 
		node_pos=nx.spring_layout(gPORT) 
		nx.draw_networkx(gPORT, node_pos,node_size=450,node_color='y',edgelist=[])
		nx.draw_networkx_edges(gPORT, node_pos,edge_color=weights,edge_cmap=viridis,edge_style="dashed")
		nx.draw_networkx_edge_labels(gPORT, node_pos, edge_labels=n_weight)
		outfn = '%s_portnet.jpg' % os.path.basename(infname)
		plt.title('Network of traffic between port numbers in %s' % os.path.basename(infname))
		plt.savefig(outfn)
		pics.append(outfn)
	writeIndex(pics)

