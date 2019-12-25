#!/usr/bin/env python3
# adapted from https://pythonprogramming.net/python-threaded-port-scanner/
# Nothing like as good as
# time sudo nmap -n -PN -sT -sU -p- 127.0.0.1
# Not shown: 131059 closed ports
# 51413/tcp open          unknown
# 68/udp    open|filtered dhcpc
# 631/udp   open|filtered ipp
# 5353/udp  open|filtered zeroconf
# 50127/udp open|filtered unknown
# Nmap done: 1 IP address (1 host up) scanned in 6949.53 seconds
# but faster at about 7 seconds for the same host

import threading
from queue import Queue
import time
import socket
import subprocess
import sys
from datetime import datetime

LASTPORT=65535
NTHREADS=250
print_lock = threading.Lock()
q = Queue()


def pscan(port):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		con = s.connect((remoteServer,port))
		with print_lock:
			print('port',port,'open')
		con.close()
	except:
		pass
		
def threader():
	while True:
		worker = q.get()
		pscan(worker)
		q.task_done()
		

def doRun():

	for x in range(NTHREADS):
		 t = threading.Thread(target=threader)
		 # classify as a daemon, so they will die when the main dies
		 t.daemon = True
		 # begins, must come after daemon definition
		 t.start()
	for worker in range(1,LASTPORT):
		q.put(worker)
	# wait until the q terminates.
	q.join()

if __name__ == "__main__":
	# Ask for input
	remoteServer    = input("Enter a remote host to scan (127.0.0.1 is default): ")
	if not '.' in remoteServer: 
		remoteServer = '127.0.0.1'
	remoteServerIP  = socket.gethostbyname(remoteServer)
	print("Please wait, scanning remote host %s \n" % remoteServerIP)
	t1 = datetime.now()
	doRun()
	t2 = datetime.now()
	total =  t2 - t1
	print ('Scanning Completed in: ', total,'secs')
