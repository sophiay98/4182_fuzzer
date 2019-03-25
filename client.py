from scapy.all import *

# mysocket = socket.socket()
# mysocket.connect(("192.168.1.11", 1338))

sport = random.randint(1024,65535)

# SYN
ip=IP(src='192.168.1.13',dst='192.168.1.11')
SYN=TCP(sport=sport,dport=65432,flags='S',seq=1000)
payload= b'\x15\x15\x15\x15'
SYNACK=sr1(ip/SYN/payload)
print(SYNACK[TCP])

def ppay(packet):
    print(packet[TCP].payload)



# ACK
my_ack = SYNACK.seq + 1
ACK=TCP(sport=sport, dport=65432, flags='A', seq=1001, ack=my_ack)
send(ip/ACK)

send(ip/TCP(dport=65432, seq=1002)/payload)
send(ip/TCP(dport=65432, seq=1006)/payload)
send(ip/TCP(dport=65432, seq=1010)/payload)
send(ip/TCP(dport=65432, seq=1014)/payload)