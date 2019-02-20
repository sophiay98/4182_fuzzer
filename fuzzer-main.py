
import sys, socket, scapy

def connect_to_server(dest,port):

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print ("Socket successfully created")
        sock.connect((dest, port))
    except:  # If fail, return null
        print("cannot connect to IP address {} at port {}".format(dest, str(port)))
        sys.exit()

    return sock

if __name__ == '__main__':

    dest = str(input("enter dest \n"))

    port = str(input("enter port \n"))

    source = str(input("enter source \n"))

    sock = connect_to_server(dest,int(port)) #opens the socket



    sock.close()

    print("success")

    exit()