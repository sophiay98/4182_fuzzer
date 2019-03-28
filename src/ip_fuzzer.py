from scapy.all import *

import pandas as pd
import numpy as np


class IPFuzzer():

    def __init__(self,source="127.0.0.1", dest="127.0.0.1", payload="./payload", verbose=0,sport=1337, dport=1338,):
        self._source = source
        self._dest = dest
        self._payload = payload
        self._dport = dport
        self._sport = sport
        self._field_val_map = {"len":"0xffff",
                               "proto":"0xff",
                               "ihl":"0xf",
                               "flags":"0b111",
                               "frag":"0b1111111111111",
                               "ttl":"0xff",
                               "tos":"0xff",
                               "id":"0xffff",
                               "chksum":"0xffff",
                               "version":"0xf",}
        self._payload_addr = payload
        self.verbose = verbose

    def _get_payload(self):
        try:
            f = open(self._payload_addr, "r")
            payloads = f.readlines()
            if len(payloads) < 1:
                f.close()
                raise IOError

            # if value in the file is not hex string
            try:
                payload = bytes.fromhex(payloads[0]) # only reads the first line of the file
                print("using payload: 0x" + payloads[0])
            except ValueError:
                print("%s cannot be parsed as hex" % (payloads[0]))
                print("changing the file to include default payload 0x00...")
                f = open(self._payload_addr, "w")
                payload = "00"
                f.write(payload)
                f.close()
                payload = bytes.fromhex("00")
        except IOError:
            f = open(self._payload_addr, "w")
            payload = bytes.fromhex("00")
            f.write("00")
            f.close()
            print("failure while reading value in the file")
            print("created new file with payload: 0x00")
        return payload

    def _fuzz_from_file(self,file,payload):
        pckts = []

        #creates pandas dataframe from the file
        try:
            fields = pd.read_csv(file)
        except FileNotFoundError:
            print("unable to read the file: %s", file)
            return pckts

        fields_dict = {col: list(fields[col]) for col in fields.columns}

        #read in csv file with the first line indicating fields' names
        for index in range(len(list(fields_dict.values())[0])):
            ip = IP(dst=self._dest,src=self._source)
            for field in fields_dict.keys():
                #set parameter if value is not null
                try:
                    val = int(fields_dict[field][index],0)
                    setattr(ip, field, val)
                except:
                    pass
                pckts.append(ip / TCP(sport=self._sport, dport=self._dport) / payload)

        return pckts

    def _fuzz_by_fields(self, fields=None,payload="0x00"):
        pckts = []
        special_fields = set()

        if not fields:
            fields = self._field_val_map.keys()

        for field in fields:
            print("fuzzing %s..."%(field))
            ip = IP(dst=self._dest,src=self._source)  # create default packet

            if field in special_fields:
                pass  # do something special
            else:
                trial = range(int(self._field_val_map[field], 0) + 1)

            for _ in trial:
                setattr(ip, field, _)
                pckts.append(ip/TCP(sport=self._sport, dport=self._dport)/payload)
        return pckts


    def fuzz(self, fields=None, file=None, all=False):
        payload = self._get_payload()
        if file:
            pckts = self._fuzz_from_file(file,payload)

        else:
            pckts = self._fuzz_by_fields(fields,payload)

        print("preparing to send %d packets" %(len(pckts)))

        for pckt in pckts:
            sendp(Ether()/pckt, verbose=self.verbose)

        print("packets sent successfully")
        return

if __name__ == "__main__":
    fuzz=IPFuzzer("127.0.0.1","127.0.0.1")
    fuzz.fuzz(["flags","ttl","version"])