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

from scapy.all import *
import time
import atexit


# VARIABLES

class Client(object):

    def __init__(self, src='192.168.1.13', dst='192.168.1.11',sport='1337',dport='1338',verbose=0):
        self.src = src
        self.dst = dst
        self.ip = IP(src=self.src, dst=self.dst)
        self.sport = int(sport)
        self.dport = int(dport)
        self.seq = 0
        self.ack = 0
        self.connected = False
        self.ack_Thread = None
        self.timeout = 5
        self.valid = 0
        self.invalid = 0
        self.total = 0
        self.verbose = verbose

    def do_ack(self, p):
        self.ack = p[TCP].seq + len(p[Raw])
        ack = self.ip / TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack)
        send(ack, verbose=self.verbose)

    def ack_rclose(self):
        self.connected = False

        self.ack += 1
        fin_ack = self.ip / TCP(sport=self.sport, dport=self.dport, flags='FA', seq=self.seq, ack=self.ack)
        ack = sr1(fin_ack, timeout=self.timeout, verbose=self.verbose)
        self.seq += 1

    def ackthread_start(self):
        self._ackThread = Thread(name='AT', target=self.sniff)
        self._ackThread.setDaemon(True)
        self._recvThread = Thread(name='RC', target=self.recv)
        self._recvThread.setDaemon(True)
        self._ackThread.start()
        self._recvThread.start()

    def recv(self):
        def test(p):
            if p[TCP] and p[TCP].payload and p[TCP].dport == self.sport and p[TCP].sport == self.dport\
                    and b"0xff" in bytes(p[TCP].payload):
                self.invalid += 1
            elif p[TCP] and p[TCP].payload and p[TCP].dport == self.sport and p[TCP].sport == self.dport\
                    and b"0x00" in bytes(p[TCP].payload):
                self.valid += 1

        sniff(filter="tcp", prn=test, store=0)

    def sniff(self):
        s = L3RawSocket()
        while self.connected:
            p = s.recv(MTU)
            if p.haslayer(TCP) and p.haslayer(Raw) \
                    and p[TCP].dport == self.sport and b'0xff' in p.payload:
                self.invalid += 1
            if p.haslayer(TCP) and p.haslayer(Raw) \
                    and p[TCP].dport == self.sport and b'0x00' in p.payload:
                self.valid += 1
            if p.haslayer(TCP) and p.haslayer(Raw) \
                    and p[TCP].dport == self.sport:
                self.do_ack(p)
            if p.haslayer(TCP) and p[TCP].dport == self.sport \
                    and p[TCP].flags & 0x01 == 0x01:
                self.ack_rclose()

        s.close()
        self._ackThread = None

    def connect(self):
        self.seq = random.randint(0, (2 ** 32) - 1)
        # SYN
        ip = IP(src=self.src, dst=self.dst)
        SYN = TCP(sport=self.sport, dport=self.dport, flags='S', seq=self.seq)
        self.seq += 1
        SYNACK = sr1(ip / SYN, timeout=self.timeout, verbose=self.verbose)
        if not SYNACK:
            raise TimeoutError
        # SYNACK.show()

        # ACK
        self.ack = SYNACK[TCP].seq + 1
        ACK = TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack)
        send(ip / ACK, verbose=self.verbose)

        self.connected = True
        self.ackthread_start()
        print("Connected to " + str(self.dst))

    def send(self, payload):
        packet = self.ip / TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack) / payload
        # packet.show()
        ack = sr1(packet, timeout=self.timeout, verbose=self.verbose)
        self.seq += len(packet[Raw])
        self.total += 1

    def close(self):
        self.connected = False

        fin = self.ip/TCP(sport=self.sport, dport=self.dport, flags='FA', seq=self.seq, ack=self.ack)
        fin_ack = sr1(fin, timeout=self.timeout, verbose=self.verbose)
        self.seq += 1

        if fin_ack:
            self.ack = fin_ack[TCP].seq + 1
        ack = self.ip/TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq,  ack=self.ack)
        send(ack, verbose=self.verbose)


# self-testing/doodling/manual input testing
if __name__ =="__main__":
    arglist = sys.argv

    try:
        src = arglist[1]
        dst = arglist[2]
        sport = arglist[3]
        dport = arglist[4]
        myclient = Client(src, dst, sport, dport)
    except IndexError:
        print("Not enough arguments given.\nThe full format is sudo python3 client.py src dst sport dport")
        print("Proceeding with default values")
        myclient = Client()

    myclient.connect()
    i = ""
    while i != "q" and i != "Q":
        time.sleep(1)
        i = input("input packet to send: ")
        if i.lower() == "q":
            break
        myclient.send(i)
    myclient.close()
    print(myclient.valid)
    print(myclient.invalid)
