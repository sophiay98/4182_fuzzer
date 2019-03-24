from scapy.all import *
import binascii
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import re

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

file_name='server_pattern'
with open(file_name, 'rb') as f:
    pattern = f.read()
print(hex(int(pattern,16)))
sniff(filter="tcp", prn=packet_callback, store=0)