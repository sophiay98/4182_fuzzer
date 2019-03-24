from scapy.all import *
import binascii
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import re
from http.server import HTTPServer

valid = 0
invalid = 0

def read_pattern(file_name="pattern"):
    with open(file_name) as f:
        pattern = f.read()
    pattern = bytes.fromhex(pattern)
    print(pattern)
    # print(pattern.encode("utf-8"))
    # if len(pattern) % 2 != 0:
    #     pattern = "0" + pattern
    return pattern


def packet_callback(packet, pattern=read_pattern()):
    if packet[TCP].payload:
        pkt = str(packet[TCP].payload)
        try:
            print("type: " + str(type(packet[IP])))
            print("IP: " + str(packet[IP].src))
        except Exception as e:
            print(e)
        try:
            if True: # packet[IP]:
                print(pattern)
                print(packet[TCP].payload)
                if pattern in bytes(packet[TCP].payload[:len(pattern)]):
                    print("wow!")
                    tcp = TCP(sport=80, dport=8000)
                    ip = IP(dst=packet[IP].src)
                    payload = "0xff"
                    response = Ether()/tcp/ip/payload
                    sendp(response)
                else:
                    print("error")

        except Exception as e:
            print(e)

pattern = read_pattern()
sniff(filter="tcp", prn=packet_callback, store=0)
port = 1338
print("Server open on localhost: " + str(port))
server = HTTPServer(('', port), None)
server.serve_forever()