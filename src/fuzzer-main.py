
import sys, socket, scapy,os
from time import sleep


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

    sock.close()

    print("success")

    exit()