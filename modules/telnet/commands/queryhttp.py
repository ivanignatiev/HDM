import logging
import socket
import pymongo
import json

class command(object):
    config = {}
    log = None
    database = None

    def __init__(self, config, database):
        self.config = config
        self.log = logging.getLogger("mitm.telnet.query")
        self.database = database
        self.log.info("query command loaded")

    def invoke(self, query, inp, out):
        if query == "":
            result = self.database.http.find()
        else:
            result = self.database.http.find(json.loads(query))

        for log in result:
            out.write(str(log))
            out.write("\n")
            out.write("\n")