#!/usr/bin/env python3
# adapted from https://pythonprogramming.net/python-threaded-port-scanner/
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
    remoteServer    = input("Enter a remote host to scan: ")
    remoteServerIP  = socket.gethostbyname(remoteServer)

    # Print a nice banner with information on which host we are about to scan
    print("-" * 60)
    print("Please wait, scanning remote host", remoteServerIP)
    print("-" * 60)


    t1 = datetime.now()
    doRun()

    t2 = datetime.now()
    total =  t2 - t1
    print ('Scanning Completed in: ', total,'secs')
