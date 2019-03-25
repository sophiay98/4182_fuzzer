import socket
from scapy.all import *


class Reservation(Packet):
    name = "ReservationPacket"
    fields_desc=[ ByteField("id", 0),
        BitField("type",None, 0),
        X3BytesField("update", 0),
        ByteField("rssiap", 0)]


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('192.168.240.1', 5000))
s.listen(1)

while True :

    conn, addr = s.accept()

    print ('Connection address:', addr)

    print ('')

    data = conn.recv(1024)
    print(data)
    conn.close()

s.close()