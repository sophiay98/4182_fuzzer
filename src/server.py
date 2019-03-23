#!/usr/bin/env python3
from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import re

def packet_callback(packet):
    if packet[TCP].payload:
        pkt = str(packet[TCP].payload)

        print(pkt)
        try:
            if packet[IP] is not None and packet[IP].dport == 7999:
                print("\n{} ----HTTP----> {}:{}:\n{}".format(packet[IP].src, packet[IP].dst, packet[IP].dport,
                                                             str(bytes(packet[TCP].payload))))
        except IndexError as e:
            print(e)


sniff(filter="tcp", prn=packet_callback, store=0)