import logging
import socket

class command(object):
    config = {}
    log = None
    database = None

    def __init__(self, config, database):
        self.config = config
        self.log = logging.getLogger("mitm.telnet.poisonstop")
        self.database = database
        self.log.info("poisonstop command loaded")

    def invoke(self, ip, inp, out):
        try:
            socket.inet_aton(ip)
            del self.config["poison"]["victim"]
            out.write("success\n")
            self.log.info("stop poisoning %s" % (ip))
        except socket.error:
            out.write("wrong ip address\n")