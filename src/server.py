from scapy.all import *
import binascii
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import re
from http.server import HTTPServer, BaseHTTPRequestHandler

def packet_callback(packet, file_name="server_pattern"):
    if packet[TCP].payload:
        pkt = str(packet[TCP].payload)

        print(pkt)
        try:
            if packet[IP] and packet[IP].dport == 80:
                if packet[TCP].payload == pattern:
                    pass
                else:
                    pass
        except Exception as e:
            print(e)

def read_pattern(file_name="server_pattern"):
    file_name='server_pattern'
    with open(file_name, 'rb') as f:
        pattern = f.read()
    print(pattern)
    print(list(pattern))
    # print(pattern.encode("utf-8"))
    print(hex(int(pattern,16)))
    # if len(pattern) % 2 != 0:
    #     pattern = "0" + pattern
    return pattern

pattern = read_pattern()
sniff(filter="tcp", prn=packet_callback, store=0)
port = 1338
print("Server open on localhost: " + str(port))
server = HTTPServer(('', port), None)
server.serve_forever()