from scapy.all import *
#eof

class IPFuzzer():
    def __init__(self,source,dest,payload=None):
        self._source = source
        self._dest = dest
        self._payload = payload
        self._field_val_map = {"len":"0xffff","proto":"0xff","ihl":"0xf",
                               "flags":"0b111","frag":"0b1111111111111",
                               "ttl":"0xff",}
        self._payload_addr = "./payload"
        #"source", "TOS", "id", "checksum"


    def _get_payload(self):
        try:
            f = open(self._payload_addr,"r")
            paylaods = f.readlines()
            f.close()
            #TODO : restriction on the length of the payload?
            return paylaods[0]
        except IOError:
            f = open(self._payload_addr, "w")
            payload = "default payload"
            f.write(payload)
            f.close()
            return payload

    def _fuzz_from_file(self,file):
        pckts = []

        try:
            f = open("./"+file,"r")
            pckts_info = f.readlines()
            #TODO: Confirm if it can be CSV format

        except IOError:
            print("Cannot open file, running default fuzzing test instead...")
            pckts = self._fuzz_by_fields()

        return pckts

    def _fuzz_by_fields(self, fields=None):
        pckts = []
        special_fields = set()

        if not fields:
            fields = self._field_val_map.keys()

        # need to modify for certain fields.

        for field in fields:
            ip = IP(dst=self._dest)  # create default packet

            if field in special_fields:
                pass  # do something special
            else:
                trial = range(int(self._field_val_map[field], 0) + 1)

            for _ in trial:
                setattr(ip, field, _)
                pckts.append(ip/TCP()/RAW(load=self._get_payload()))
        return pckts


    def fuzz(self, fields=None, file=None):

        if file:
            pckts = self._fuzz_from_file(file)

        else:
            pckts = self._fuzz_by_fields(fields)

        for pckt in pckts:
            sendp(Ether()/pckt)




# def create_packets(self,field):
#     ip = IP(dst=self._dest)
#     ips = []
#
#     #fuzz src?TOS?identification?checksum?
#     if field in ["source", "TOS", "id", "checksum"]:
#         pass
#
#     #Internet Header Length which is the length of entire IP header.
#     elif field == "ihl":
#         for ihl in range(int("0xf", 0) + 1):
#             new_pckt = ip
#             new_pckt.ihl=ihl
#             ips.append(new_pckt)
#
#     #fuzz flags
#     # three-bit used to identify and control fragments. In this 3-bit flag, the bit 0 is always set to '0'.
#     elif field == "flag":
#         for flag in range(int("0b111", 0) + 1):
#             new_pckt = ip
#             new_pckt.flags=flag
#             ips.append(new_pckt)
#
#
#     #This offset provides the location of the fragment in the original IP Packet.
#     #naive iterate through all possible vals
#     elif field == "frag":
#         for frag in range(int("0b1111111111111", 0)+1):
#             new_pckt = ip
#             new_pckt.frag = frag
#             ips.append(new_pckt)
#
#     # naive iterate through all possible vals
#     elif field == "ttl":
#         for ttl in range(int("0xff", 0)+1):
#             new_pckt = ip
#             new_pckt.frag = ttl
#             ips.append(new_pckt)
#
#     # naive iterate through all possible vals
#     # optimize using actual vaild vals and 1 invalid?
#     elif field == "proto":
#         for proto in range(int("0xff", 0) + 1):
#             new_pckt = ip
#             new_pckt.proto = proto
#             ips.append(new_pckt)
#
#     #fuzz length to create length mismatch?
#     #optimize this so there exist mismatch
#     #currently producing 6553 packets.
#     #producing 4 would be enough?
#     #Length of entire IP packet which includes IP header and encapsulated data.
#
#     if field == "length":
#         for length in range(int("0xffff",0)+1,0):
#             ip.len = length
#             new_pckt = ip
#             ips.append(new_pckt)
#
#     return ips


fuzz=IPFuzzer("127.0.0.1","127.0.0.1")
fuzz.fuzz(["flags"])
#fuzz.auto_testing()

#use as a shell
#end of file handling
#mention the flaw in docu
