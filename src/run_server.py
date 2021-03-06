
import socket
from scapy.all import *
import atexit

# find local host internal address, set port to 1338
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
ip = s.getsockname()[0]
s.close()
port = 1338

valid = 0
invalid = 0

# print valid and invalid # of packets before exit, -1 in invalid to disregard connection closing packet
def print_v_i():
    print("# of valid packets: " + str(valid))
    print("# of invalid packets: " + str(max(0,invalid)))
atexit.register(print_v_i)

try:
    pattern = open("pattern.txt", 'r')
    pattern = pattern.read()
except IOError:
    print("no pattern.txt found. falling back to \x00.")
    pattern = "\x00"

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # wait for the ip:port to be available, and open port when available.
    s.settimeout(None)
    while True:
        try:
            s.bind((ip, int(port)))
            break
        except Exception as e:
            time.sleep(1)
            continue
    s.listen(1)
    print("server ready!")
    print("Listening on port: " + str(port))
    while True:
        conn, addr = s.accept()

        # on exit, close connection
        def close_conn():
            conn.close()
        atexit.register(close_conn)

        with conn:
            print('Connection address:', addr)
            data = ''
            while conn:
                # max data length = 128 bytes
                data = str(conn.recv(128))

                #server doesn't accept empty payload
                if data != "b''":
                    print(data)
                else:
                    continue

                #send valid/invalid
                if pattern in data[:len(pattern)]:
                    print("valid!")
                    valid += 1
                    conn.sendall(b"0x000x000x000x00")
                else:
                    print("invalid!")
                    invalid += 1
                    conn.sendall(b"0xff0xff0xff0xff")

                #data parsing
                if not data:
                    break
                if not data.endswith('\r\n'):
                    continue
                lines = data.split('\r\n')
                for line in lines:
                    print(line)
                data = ''

