import logging
import os
import nfqueue
import socket
import threading
import time
from scapy.all import *

class bootstrap(object):
    config = {}
    log = None
    database = None
    traffic_controller = None

    def __init__(self, config, database):
        self.config = config
        self.log = logging.getLogger("mitm.traffic")
        self.database = database
        self.start_to_control()
        self.log.info("traffic module loaded")

    def start_to_control(self):
        self.traffic_controller = Traffic(self.config, self.log, self.database)
        self.traffic_controller.start()

    def invoke(self):
        pass

    def close(self):
        if self.traffic_controller:
            self.traffic_controller.stop()
            self.traffic_controller.join()
        self.log.info("traffic module has downed")

class Traffic(threading.Thread):
    running = True
    config = None
    database = None
    log = None
    queue = None
    plugins_mods = []
    plugins = []

    def __init__(self, config, log, database):
        super(Traffic, self).__init__()
        self.config = config
        self.log = log
        self.database = database
        self.running = True
        self.queue = nfqueue.queue()
        self.queue.open()
        self.queue.bind(socket.AF_INET)
        self.queue.set_callback(self.callback)
        self.queue.create_queue(0)
        self.load_plugins()

    def load_plugins(self):
        self.log.info("traffic plugins loading")

        self.plugins_mods = [__import__("modules.traffic.plugins.%s" % (name), fromlist=["*"])
                                for name in self.config.get("traffic").get("plugins")]

        self.plugins = [getattr(mod_plugin, "plugin")(self.config, self.database) for mod_plugin in self.plugins_mods]

    def init_system_env(self):
        os.system('sysctl net.ipv4.ip_forward=1')
        os.system('iptables -I FORWARD -j NFQUEUE')

    def callback(self, i, payload):

        data = payload.get_data()
        packet = IP(data)

        modified = False
        for plugin in self.plugins:
            plugin.invoke(packet)
            modified = modified or plugin.modified

        if modified:
            payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(packet), len(packet))
            return True

        payload.set_verdict(nfqueue.NF_ACCEPT)
        return True

    def run(self):
        self.log.info("traffic nfqueue controlling start")
        self.init_system_env()
        while self.running:
            self.queue.process_pending(self.config.get("traffic").get("processing_count"))
            time.sleep(self.config.get("traffic").get("delay"))

    def stop(self):
        self.running = False
        os.system('sysctl net.ipv4.ip_forward=0')
        os.system('iptables -F')
        os.system('iptables -X')
        self.queue.unbind(socket.AF_INET)
        self.queue.close()