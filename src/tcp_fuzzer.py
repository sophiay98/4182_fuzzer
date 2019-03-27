
from scapy.all import *
import random
import pandas as pd
import numpy as np

"""FROM toschprod.wordpress.com

    Source port: It is the port used by client to sent the packet.
    Destination port: It is the port used by the server for the communication
    Sequence number: If the SYN flag is set, it is the initial sequence number. If it isn’t, then it is the accumulated sequence number of the first data byte of this packet for the current session.
    Acknoledgment number: If the ACK flag is set, then it is the value of the next sequence number that the receiver is expecting.
    Data offset: It specifies the size of the TCP header in 32-bit words.
    Reserved: This field is reserved for a future for a potential improvement of the protocol TCP (should be set to zero).
    Flags (NS/CWR/ECE/URG/ACK/PSH/RST/SYN/FIN): Also known as control bit, flags are notifications and gives signal the purpose of the packet. URG indicates that the Urgent pointer field is significant. ACK indicates that the Acknowledgment field is significant. All packets after the initial SYN packet sent by the client should have this flag set. RST reset the connection. SYN synchronize sequence numbers and FIN indicates no more data will be sent from sender.
    Windows Size: It specifies the number of bytes that the receiver is currently willing to receive.
    Checksum: The 16-bit checksum field is used for error-checking of the header and data.
    Urgent Pointer: If the URG flag is set, then this 16-bit field is an offset from the sequence number indicating the last urgent data byte
    Options: The length of this field is determined by the data offset field. This field is used for providing more information about the packet.
    Padding: The TCP header padding is used to ensure that the TCP header ends and data begins on a 32 bit boundary. The padding is composed of zeros.


"""


class TCPFuzzer(object):
    def __init__(self, source="127.0.0.1", dest="127.0.0.1", sport=1337, dport=1338, payload=None, fields=[], verbose=0):
        self._source = source
        self._dest = dest
        self._payload = "1"
        self.fields = {
            "seq": (0, 2 ** 32),
            "ack": (0, 2 ** 32),
            "dataofs": (0, 16),
            "reserved": (0, 7),
            "flags": (0, 2 ** 9 - 1),
            "window": (0, 10000),
            "chksum": (0, 2 ** 16),
            "urgptr": (0, 2 ** 16),
            "options": (0, 2 ** 100)
        }
        self.tcp = TCP(sport=sport,dport=dport)
        self.ip = IP(src=self._source, dst=self._dest)
        self.sent = 0
        self.verbose = verbose
        self._payload_addr = "./payload"

    def create_packets(self):
        pass

    def _get_payload(self):
        try:
            f = open(self._payload_addr, "r")
            payloads = f.readlines()
            if len(payloads) < 1:
                f.close()
                raise IOError
            # TODO : restriction on the length of the payload?

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

    def _fuzz_from_file(self, file, payload):
        pckts = []

        # creates pandas dataframe from the file
        try:
            fields = pd.read_csv(file)
        except FileNotFoundError:
            print("unable to read the file: %s", file)
            return pckts

        fields_dict = {col: list(fields[col]) for col in fields.columns}

        # read in csv file with the first line indicating fields' names
        ip = IP(dst=self._dest, src=self._source)
        for index in range(len(fields_dict.values())-1):
            tcp = self.tcp
            for field in fields_dict.keys():
                # set parameter if value is not null
                if not np.isnan(fields_dict[field][index]):
                    setattr(tcp, field, fields_dict[field][index])
                pckts.append(ip / tcp / payload)

        return pckts

    def fuzz(self, field_name='dport', all=False, num_trials=10,file=None):
        tcp = self.tcp
        r = []
        self._payload = self._get_payload()
        if all:
            for f in self.fields.keys():
                self.fuzz(f)

        if file:
            r = self._fuzz_from_file(file,self._payload)
        else:
            if self.fields[field_name][1] - self.fields[field_name][0] > 10000:
                trial = [random.randint(self.fields[field_name][0], self.fields[field_name][1]) for x in range(num_trials)]
            else:
                trial = range(self.fields[field_name][0], self.fields[field_name][1])

            for i in trial:
                setattr(tcp, field_name, i)
                r.append(Ether() / self.ip / tcp / self._payload)
        for packet in r:
            sendp(packet, verbose=self.verbose)
            self.sent += 1

    def send(self, packet_list):
        for packet in packet_list:
            self.sent += 1
            sendp(packet, verbose=self.verbose)

if __name__ == "__main__":
    t = TCPFuzzer()
    t.fuzz(all=True)