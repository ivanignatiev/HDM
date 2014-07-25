import logging
import socket

class command(object):
    config = {}
    log = None
    database = None

    def __init__(self, config, database):
        self.config = config
        self.log = logging.getLogger("mitm.telnet.poisonstart")
        self.database = database
        self.log.info("poisonstart command loaded")

    def invoke(self, ip, inp, out):
        try:
            socket.inet_aton(ip)
            self.config["poison"]["victim"] = ip
            out.write("success\n")
            self.log.info("start poisoning %s" % (ip))
        except socket.error:
            out.write("wrong ip address\n")