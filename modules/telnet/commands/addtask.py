import logging

class command(object):
    config = {}
    log = None
    database = None

    def __init__(self, config, database):
        self.config = config
        self.log = logging.getLogger("mitm.telnet.addtask")
        self.database = database
        self.log.info("addtask command loaded")

    def invoke(self, args, inp, out):
        out.write("success\n")
        pass