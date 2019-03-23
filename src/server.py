#!/usr/bin/env python3
from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import re

def packet_callback(packet):
    if packet[TCP].payload:
        pkt = str(packet[TCP].payload)

        print(pkt)

sniff(filter="tcp", prn=packet_callback, store=0)