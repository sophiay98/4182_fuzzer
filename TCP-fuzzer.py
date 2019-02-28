from scapy.all import *


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


class IPFuzzer(object):
    def __init__(self,source="127.0.0.1",dest="192.168.1.19",payload=None,fields=[]):
        self._source = source
        self._dest = dest
        self._payload = payload
        self.sport = (0,10000)
        self.dport = (0,10000)
        self.seq= (0, 2 ** 32)
        self.ack = (0, 2 ** 32)
        self.dataoffs = None
        self.reserved= 0
        self.flags = "0" * 9
        self.window = (0,10000)
        self.chksum = "0" * 32
        self.urgptr = 0
        self.options = ({})

    def create_packets(self):
        pass

    def fuzz_sport(self):
        pass

    def fuzz_dport(self):
        pass

    def fuzz_seq(self):
        pass

    def fuzz_ack(self):
        pass

    def fuzz_dataoffs(self):
        pass

    def fuzz_reserved(self):
        pass

    def fuzz_flags(self):
        pass

    def fuzz_window(self):
        pass

    def fuzz_chksum(self):
        pass

    def fuzz_urgptr(self):
        pass

    def fuzz_options(self):
        pass



