import logging
import datetime
from scapy.all import *
import pymongo
import bson

class SerializablePacket(Packet):
    def get_as_dict(self):
        dd = {}
        f = []
        for fn,fv in self.fields.items():
            fld = self.get_field(fn)
            if isinstance(fv, Packet):
                fv = fv.command()
            elif fld.islist and fld.holds_packets and type(fv) is list:
                fv = "[%s]" % ",".join( map(Packet.command, fv))
            else:
                fv = repr(fv)
            f.append("%s=%s" % (fn, fv))
        c = "%s(%s)" % (self.__class__.__name__, ", ".join(f))
        pc = self.payload.command()
        if pc:
            c += "/"+pc
        return c

class plugin(object):
    log = None
    config = None
    database = None
    modified = False

    def __init__(self, config, database):
        self.log = logging.getLogger("mitm.traffic.logger")
        self.config = config
        self.database = database
        self.log.info("logger plugin loaded")

    def serialize(self, payload, result = {}):
        if isinstance(payload, NoPayload):
            return result
        packet_dict = result
        packet_key = payload.__class__.__name__
        packet_dict[packet_key] = {}
        for field_name, field_value in payload.fields.items():
            field_type = payload.get_field(field_name)
            if isinstance(field_value, Packet):
                continue
                packet_dict[packet_key][field_name] = self.serialize(field_value)
            elif field_type.islist and field_type.holds_packets and type(field_value) is list:
                continue
                #packet_dict[packet_key][field_name] = map(self.serialize, field_value)
            else:
                packet_dict[packet_key][field_name] = repr(field_value)
        return self.serialize(payload.payload, packet_dict)

    def invoke(self, packet):
        self.modified = False
        packet_dict = self.serialize(packet)

        print packet_dict

        try:
            self.database.log.insert(packet_dict, safe=True)
        except pymongo.errors.DuplicateKeyError:
            if self.config.get("traffic").get("allow_dublicates"):
                packet_dict["_id"] = bson.objectid.ObjectId()
                print packet_dict
                self.database.log.insert(packet_dict, safe=True)

        del packet_dict
