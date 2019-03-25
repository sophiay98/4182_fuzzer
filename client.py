from scapy.all import *

sport = random.randint(1024,65535)

# SYN
ip=IP(src='192.168.1.13',dst='192.168.1.11')
SYN=TCP(sport=sport,dport=8909,flags='S',seq=1000)
SYNACK=sr1(ip/SYN)

# ACK
my_ack = SYNACK.seq + 1
ACK=TCP(sport=sport, dport=8909, flags='A', seq=1001, ack=my_ack)
send(ip/ACK)