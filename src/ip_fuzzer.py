from scapy.all import *

#TODO: use as a shell
#TODO: end of file handling (eof)
#TODO: mention the flaw in documentation

#max payload size
#regulate file type and input type


class IPFuzzer():
    def __init__(self,source="127.0.0.1", dest="127.0.0.1", payload=None):
        self._source = source
        self._dest = dest
        self._payload = payload
        self._field_val_map = {"len":"0xffff","proto":"0xff","ihl":"0xf",
                               "flags":"0b111","frag":"0b1111111111111",
                               "ttl":"0xff"}
        self._payload_addr = "./payload"
        #"source", "TOS", "id", "checksum"


    def _get_payload(self):
        try:
            f = open(self._payload_addr,"r")
            paylaods = f.readlines()
            if len(paylaods) < 1:
                raise IOError
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


fuzz=IPFuzzer("127.0.0.1","127.0.0.1")
fuzz.fuzz(["flags"])