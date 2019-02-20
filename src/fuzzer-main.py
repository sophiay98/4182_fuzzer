
import sys, socket, os
from time import sleep
from scapy.all import *


def connect_to_server(dest,port):

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print ("Socket successfully created")
        s.connect((dest, port))
    except:  # If fail, return null
        print("cannot connect to IP address {} at port {}".format(dest, str(port)))
        sys.exit()

    return s

if __name__ == '__main__':

    dest = str(input("enter dest \n"))

    port = str(input("enter port \n"))

    source = str(input("enter source \n"))

    sock = connect_to_server(dest,int(port))
    mystream = StreamSocket(sock)
    some_packet=IP(dst="10.1.1.1")/TCP(dport=9000)/fuzz(Raw())

    sock.close()

    print("success")

    exit()