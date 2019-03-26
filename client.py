from scapy.all import *

# mysocket = socket.socket()
# mysocket.connect(("192.168.1.11", 1338))

# sport = random.randint(1024,65535)
#
# # SYN
# ip=IP(src='192.168.1.13',dst='192.168.1.11')
# SYN=TCP(sport=sport,dport=65432,flags='S',seq=1000)
# payload= b'\x15\x15\x15\x15'
# SYNACK=sr1(ip/SYN/payload)
# print(SYNACK[TCP])
#
# def ppay(packet):
#     print(packet[TCP].payload)
#
#
#
# # ACK
# my_ack = SYNACK.seq + 1
# ACK=TCP(sport=sport, dport=65432, flags='A', seq=1001, ack=my_ack)
# send(ip/ACK)
#
# send(ip/TCP(dport=65432, seq=1002)/payload)
# send(ip/TCP(dport=65432, seq=1006)/payload)
# send(ip/TCP(dport=65432, seq=1010)/payload)
# send(ip/TCP(dport=65432, seq=1014)/payload)

# !/usr/bin/env python
from scapy.all import *
import time


# VARIABLES

class Client(object):

    def __init__(self, ip=None, tcp=None):
        self.src = '192.168.1.13'
        self.dst = '192.168.1.11'
        if not ip:
            self.ip = IP(src=self.src, dst=self.dst)
        else:
            self.ip = ip
        self.sport = 1337
        self.dport = int(1338)
        self.seq = 0
        self.ack = 0
        self.connected = False
        self.ack_Thread = None
        self.timeout = 5

    def do_ack(self, p):
        self.ack = p[TCP].seq + len(p[Raw])
        ack = self.ip / TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack)
        send(ack)

    def ack_rclose(self):
        self.connected = False

        self.ack += 1
        fin_ack = self.ip / TCP(sport=self.sport, dport=self.dport, flags='FA', seq=self.seq, ack=self.ack)
        ack = sr1(fin_ack, timeout=self.timeout)
        self.seq += 1

    def ackthread_start(self):
        self._ackThread = Thread(name='AT', target=self.sniff)

        self._ackThread.start()

    def sniff(self):
        s = L3RawSocket()
        while self.connected:
            p = s.recv(MTU)
            if p.haslayer(TCP) and p.haslayer(Raw) \
                    and p[TCP].dport == self.sport:
                print(p)
                self.do_ack(p)
            if p.haslayer(TCP) and p[TCP].dport == self.sport \
                    and p[TCP].flags & 0x01 == 0x01:
                self.ack_rclose()

        s.close()
        self._ackThread = None

    def connect(self):
        self.seq = random.randrange(0, (2 ** 32) - 1)
        # SYN
        ip = IP(src=self.src, dst=self.dst)
        SYN = TCP(sport=self.sport, dport=self.dport, flags='S', seq=self.seq)
        self.seq += 1
        SYNACK = sr1(ip / SYN, timeout=self.timeout)
        if not SYNACK:
            raise TimeoutError
        SYNACK.show()

        # ACK
        self.ack = SYNACK[TCP].seq + 1
        ACK = TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack)
        send(ip / ACK)

        self.connected = True
        self.ackthread_start()
        print("Connected to " + str(self.dst))

    def send(self, payload):
        packet = self.ip / TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack) / payload
        packet.show()
        ack = sr1(packet, timeout=self.timeout)
        self.seq += len(packet[Raw])

    def close(self):
        self.connected = False

        fin = self.ip/TCP(sport=self.sport, dport=self.dport, flags='FA', seq=self.seq, ack=self.ack)
        fin_ack = sr1(fin, timeout=self.timeout)
        self.seq += 1

        if fin_ack:
            self.ack = fin_ack[TCP].seq + 1
        ack = self.ip/TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq,  ack=self.ack)
        send(ack)


if __name__ =="__main__":
    myclient = Client()
    myclient.connect()
    myclient.send("wow!")
    time.sleep(1)
    myclient.send(b'\x15')
    i = ""
    while i != "q" and i != "Q":
        i = input("input packet to send: ")
        myclient.send(i)
    myclient.close()
