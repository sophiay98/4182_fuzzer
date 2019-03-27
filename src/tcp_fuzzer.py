from scapy.all import *
import random

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
    def __init__(self, source="127.0.0.1", dest="127.0.0.1", payload=None, fields=[]):
        self._source = source
        self._dest = dest
        self._payload = "1"
        self.fields = {
            "sport": (0, 10000),
            "dport": (0, 10000),
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
        self.tcp = TCP(sport=80, dport=8000)
        self.ip = IP(src=self._source, dst=self._dest)
        self.sent = 0

    def create_packets(self):
        pass

    def fuzz(self, field_name='dport', all=False, num_trials=10):
        tcp = self.tcp
        r = []
        if all:
            for f in self.fields.keys():
                self.fuzz(f)

        if self.fields[field_name][1] - self.fields[field_name][0] > 10000:
            trial = [random.randint(self.fields[field_name][0], self.fields[field_name][1]) for x in range(num_trials)]
        else:
            trial = range(self.fields[field_name][0], self.fields[field_name][1])

        for i in trial:
            setattr(tcp, field_name, i)
            r.append(Ether() / self.ip / tcp / self._payload)
        for packet in r:
            sendp(packet)
            self.sent += 1

    def send(self, packet_list):
        for packet in packet_list:
            self.sent += 1
            sendp(packet)

t = TCPFuzzer()
t.fuzz(all=True)