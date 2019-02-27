import scapy

class IPFuzzer(object):
    def __init__(self,source="127.0.0.1",dest="192.168.1.19",payload=None,fields=[]):
        self._source = source
        self._dest = dest
        self._payload = payload
        self.sport = 20
        self.dport = 80
        self.seq= 0
        self.ack = 0
        self.dataofs = None
        self.reserved= 0
        self.flags = 2
        self.window = 8192
        self.chksum = None
        self.urgptr = 0
        self.options = ({})

    def create_packets(self):


