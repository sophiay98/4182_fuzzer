
import socket
from scapy.all import *

ip = '192.168.1.11'
port = 1338




def sniff(self):
    s = L3RawSocket()
    while self.connected:
        p = s.recv(MTU)
        if p.haslayer(TCP) and p.haslayer(Raw) \
                and p[TCP].dport == self.sport:
            self.do_ack(p)
        if p.haslayer(TCP) and p[TCP].dport == self.sport \
                and p[TCP].flags & 0x01 == 0x01:  # FIN
            self.ack_rclose()

    s.close()
    self._ackThread = None

pattern = "asd"
sock = L3RawSocket()
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(None)
    while True:
        try:
            s.bind((ip, int(port)))
            break
        except Exception as e:
            continue
    s.listen(1)
    print("server ready!")
    print("Listening on port: " + str(port))
    while True:
        conn, addr = s.accept()
        with conn:
            print('Connection address:', addr)
            data = ''
            while conn:
                data = str(conn.recv(1024))
                if data != "b''":
                    print(data)
                    continue
                if pattern in data:
                    print("valid!")
                    conn.sendall(b"0x00asdf")
                else:
                    print("invalid!")
                    conn.sendall(b"0xffasdf")
                if not data:
                    break
                if not data.endswith('\r\n'):
                    continue
                lines = data.split('\r\n')
                for line in lines:
                    print(line)
                data = ''
