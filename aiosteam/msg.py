import struct

from steam.protobufs import steammessages_base_pb2
from steam.protobufs import steammessages_clientserver_pb2
from steam.protobufs import steammessages_clientserver_2_pb2

from .enums import EUniverse, EResult
from .enums.emsg import EMsg


protobuf_mask = 0x80000000
obfuscation_mask = 0xCAFEBABE #0xBAADF00D


def protobuf(msg):
    globals().setdefault('__protolookup__', {
        "order": [
            steammessages_base_pb2,
            steammessages_clientserver_pb2,
            steammessages_clientserver_2_pb2
            ],
        "root": {},
        })
    base = __protolookup__
    emsg = EMsg(msg)

    if emsg == EMsg.Multi: return steammessages_base_pb2.CMsgMulti

    # TODO: Need change emsg name to match protobuf class name exactlly.
    name = ("CMsg" + emsg.name).lower()
    for module in base["order"]:
        base["root"].setdefault(module.__name__, dict(
            map(lambda i: [i[0].lower(), i[1]], filter(lambda i: "CMsg" in i[0], module.__dict__.items()))
            ))
        prototype = base["root"][module.__name__].get(name, None)
        if prototype: return prototype


def dumps(m):
    if type(m) == bytes: return m
    if type(m) == str: return m.encode("ascii")
    if type(m) == dict: m = Message(m)
    return m.SerializeToString()

def pack(packet):
    return dumps(packet)

def loads(s):
    m, = struct.unpack_from("<I", s)
    m &= ~protobuf_mask
    return Message({"msg": m, "data": s})

def unpack(s):
    return loads(s)


class MessageHeader(object):
    msg = EMsg.Invalid
    size = 0
    version = 2
    target_jobid = -1
    source_jobid = -1
    header_canary = 239
    steamid = -1
    client_sessionid = -1
    def __init__(self, msg, extended=False):
        self.extended = extended
        self.msg = EMsg(msg)
        self.packstr = "<Iqq" if not extended else "<IBHqqBqi"
        self.size = 20 if not extended else 36
    def SerializeToString(self):
        if not self.extended:
            return struct.pack(self.packstr, self.msg, self.target_jobid, self.source_jobid)
        return struct.pack(self.packstr,
                           self.msg,
                           self.size,
                           self.version,
                           self.target_jobid,
                           self.source_jobid,
                           self.header_canary,
                           self.steamid,
                           self.client_sessionid)
    def ParseFromString(self, s):
        if self.extended:
            (msg,
             self.size,
             self.version,
             self.target_jobid,
             self.source_jobid,
             self.header_canary,
             self.steamid,
             self.client_sessionid,
             ) = struct.unpack_from(self.packstr, s)
        else:
            msg, self.target_jobid, self.source_jobid = struct.unpack_from(self.packstr, s)
        if self.extended and (self.size != 36 or self.version != 2):
            raise RuntimeError("MessageHeader parse failed.")
        self.msg = EMsg(msg)


class MessageProtoBuf(object):
    def __getattr__(self, k):
        attr = self.__dict__.get(k, None)
        if attr: return attr
        return getattr(self.data, k)
    def __setattr__(self, k, v):
        data = self.__dict__.get("data", None)
        if hasattr(data, k):
            return setattr(self.data, k, v)
        self.__dict__[k] = v
class MessageProtoBufHeader(MessageProtoBuf):
    msg = EMsg.Invalid
    size = 8
    def __init__(self, msg=EMsg.Invalid):
        self.data = steammessages_base_pb2.CMsgProtoBufHeader()
        self.msg = EMsg(msg)
        self.packstr = "<II"    # size:8
    def SerializeToString(self):
        header_data = self.data.SerializeToString()
        return struct.pack(self.packstr, int(self.msg)|protobuf_mask, len(header_data)) + header_data
    def ParseFromString(self, s):
        msg, header_length = struct.unpack_from(self.packstr, s)
        self.msg = EMsg(msg & (protobuf_mask - 1))
        size, self.size = self.size, self.size + header_length
        self.data.ParseFromString(s[size:self.size])
class MessageProtoBufBody(MessageProtoBuf):
    msg = EMsg.Invalid
    def __init__(self, msg):
        prototype = protobuf(int(msg))
        self.data = prototype() if prototype else None
        if prototype: self.msg = msg
    def SerializeToString(self):
        return self.data.SerializeToString()
    def ParseFromString(self, s):
        self.data.ParseFromString(s)


class Message(object):
    def __init__(self, packet):
        self.protobuf = False
        self.data = b""
        self.msg = EMsg(packet["msg"])
        body = globals().get(self.msg.name, None)
        if body:
            extended = False
            if not self.msg in (EMsg.ChannelEncryptRequest,
                                EMsg.ChannelEncryptResponse,
                                EMsg.ChannelEncryptResult):
                extended = True
            self.header = MessageHeader(self.msg, extended)
            self.body = body()
        else:
            self.protobuf = True
            self.header = MessageProtoBufHeader(self.msg)
            self.body = MessageProtoBufBody(self.msg)
        if packet.get("data", None):
            self.ParseFromString(packet["data"])
        else:
            self.update(packet)
    def update(self, packet):
        # from ValvePython/steam:proto_fill_from_dict
        def __setattr__(proto, k, v):
            if not self.protobuf:
                return setattr(proto, k, v)
            fields = proto.DESCRIPTOR.fields_by_name
            desc, item = fields[k], getattr(proto, k)
            if desc.type == desc.TYPE_MESSAGE:
                if desc.label == desc.LABEL_REPEATED:
                    for i in v:
                        _item = item.add()
                        for _k, _v in i.items():
                            __setattr__(_item, _k, _v)
                else:
                    for _k, _v in v.items():
                        __setattr__(item, _k, _v)
            else:
                if type(v) == list:
                    getattr(proto, k).extend(list(v))
                else:
                    setattr(proto, k, v)

        header, body = (self.header, self.body) if not self.protobuf else (self.header.data, self.body.data)
        for k,v in packet.get("header", {}).items():
            __setattr__(header, k, v)
        for k,v in packet.get("body", {}).items():
            __setattr__(body, k, v)
    def SerializeToString(self):
        return self.header.SerializeToString() + self.body.SerializeToString()
    def ParseFromString(self, s):
        try:
            self.header.ParseFromString(s)
            if self.body.msg != EMsg.Invalid:
                self.body.ParseFromString(s[self.header.size:])
        except Exception as e:
            self.data = s



class ChannelEncryptRequest(object):
    msg = EMsg.ChannelEncryptRequest
    version = 1
    universe = EUniverse.Invalid
    challenge = b""
    def SerializeToString(self):
        return struct.pack("<II", self.version, self.universe) + self.challenge
    def ParseFromString(self, s):
        self.version, universe, = struct.unpack_from("<II", s)
        self.universe = EUniverse(universe)
        if len(s) > 8: self.challenge = s[8:]


class ChannelEncryptResponse(object):
    msg = EMsg.ChannelEncryptResponse
    version = 1
    key_size = 128
    key = b''
    crc = 0
    def SerializeToString(self):
        return struct.pack("<II128sII",
                           self.version,
                           self.key_size,
                           self.key,
                           self.crc,
                           0
                           )
    def ParseFromString(self, s):
        (self.version,
         self.key_size,
         self.key,
         self.crc,
         _,
         ) = struct.unpack_from("<II128sII", s)


class ChannelEncryptResult(object):
    msg = EMsg.ChannelEncryptResult
    eresult = EResult.Invalid
    def SerializeToString(self):
        return struct.pack("<I", self.eresult)
    def ParseFromString(self, s):
        (result,) = struct.unpack_from("<I", s)
        self.eresult = EResult(result)
