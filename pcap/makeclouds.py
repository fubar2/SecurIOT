from scapy.all import *
from wordcloud import WordCloud
from collections import Counter
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
import socket
import os
from random import randint

infname = '/home/ross/rossgit/pcap/eg2.pcap'
infname = '/home/ross/rossgit/pcap/example.pcap'

pnames = ['IP','TCP','ARP','UDP','ICMP']
pobj = [IP,TCP,ARP,UDP,ICMP]

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
                    bingo = True
                if bingo:
                    continue
    return(seenIP,seenPORT)

          
def processPcap(seenIP,seenPORT,deens):
    for i,proto in enumerate(pobj):
        pn = pnames[i]
        for nsauce in seenIP[pn].keys():
            kl = len(seenIP[pn][nsauce].keys())
            print('###for',nsauce,'got',kl)
            if kl > 1:
                sf,newsaucen = lookup(seenIP[pn][nsauce],nsauce,deens) # expensive operation so moved here
                # print(newsaucen,':',sf)
                outfn = '%s_%s_wordcloud_%s.png' % (newsaucen,pn,os.path.basename(infname))
                wc = WordCloud(background_color="white",width=1200, height=1000,max_words=200,
                 min_font_size=20,
				color_func=random_color_func).generate_from_frequencies(sf)
                f = plt.figure(figsize=(10, 10))
                plt.imshow(wc, interpolation='bilinear')
                plt.axis('off')
                plt.title('%s %s destination word cloud' % (nsauce,pn))
                plt.show()
                f.savefig(outfn, bbox_inches='tight')
    for sport in seenPORT.keys():
        kl = len(seenPORT[sport].keys())
        print('###for',sport,'got',kl)
        sf = seenPORT[sport]
        s,p = sport.split('_')
        sname = deens.get(s,s)
        snameport = '%s_port_%s' % (sname,p)
        if kl > 5:
            print('sport=',snameport,'sf=',sf)
            outfn = '%s_wordcloud_%s.png' % (snameport,os.path.basename(infname))
            wc = WordCloud(background_color="white",width=1200, height=1000,
				max_words=200,min_font_size=10,
				color_func=random_color_func).generate_from_frequencies(sf)
            f = plt.figure(figsize=(10, 10))
            plt.imshow(wc, interpolation='bilinear')
            plt.axis('off')
            plt.title('%s destination port word cloud' % (snameport))
            plt.show()
            f.savefig(outfn, bbox_inches='tight')
    return(deens)


    
if __name__=="__main__":
    seenIP,seenPORT = readPcap(infname,{},{})
    print('## reading done')
    deens = processPcap(seenIP,seenPORT,{})
    print(seenIP)
    print(seenPORT)
    print(deens)
