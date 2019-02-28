from scapy.all import *
class IPFuzzer():
    def __init__(self,source,dest,payload=None,fields=[]):
        self._source = source
        self._dest = dest
        self._payload = payload
        self._fields = fields
    def create_packets(self,field):
        ip = IP(dst=self._dest)
        ips = []

        #fuzz src?TOS?identification?checksum?
        if field in ["source", "TOS", "id", "checksum"]:
            pass

        #Internet Header Length which is the length of entire IP header.
        elif field == "ihl":
            for ihl in range(int("0xf", 0) + 1):
                new_pckt = ip
                new_pckt.ihl=ihl
                ips.append(new_pckt)

        #fuzz flags
        # three-bit used to identify and control fragments. In this 3-bit flag, the bit 0 is always set to '0'.
        elif field == "flag":
            for flag in range(int("0b111", 0) + 1):
                new_pckt = ip
                new_pckt.flags=flag
                ips.append(new_pckt)


        #This offset provides the location of the fragment in the original IP Packet.
        #naive iterate through all possible vals
        elif field == "frag":
            for frag in range(int("0b1111111111111", 0)+1):
                new_pckt = ip
                new_pckt.frag = frag
                ips.append(new_pckt)

        # naive iterate through all possible vals
        elif field == "ttl":
            for ttl in range(int("0xff", 0)+1):
                new_pckt = ip
                new_pckt.frag = ttl
                ips.append(new_pckt)

        # naive iterate through all possible vals
        # optimize using actual vaild vals and 1 invalid?
        elif field == "proto":
            for proto in range(int("0xff", 0) + 1):
                new_pckt = ip
                new_pckt.proto = proto
                ips.append(new_pckt)

        #fuzz length to create length mismatch?
        #optimize this so there exist mismatch
        #currently producing 6553 packets.
        #producing 4 would be enough?
        #Length of entire IP packet which includes IP header and encapsulated data.

        if field == "length":
            for length in range(int("0xffff",0)+1,0):
                ip.len = length
                new_pckt = ip
                ips.append(new_pckt)

        return ips



    def auto_testing(self):
        for field in self._fields:
            ips = self.create_packets(field)
            for ip in ips:
                sendp(Ether()/ip)

fuzz=IPFuzzer("127.0.0.1","127.0.0.1",fields=["length","proto","flag"])
fuzz.auto_testing()