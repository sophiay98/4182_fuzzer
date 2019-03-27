import sys

from src.tcp_fuzzer import TCPFuzzer
from src.ip_fuzzer import IPFuzzer
from src.app_fuzzer import APPFuzzer
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Fuzzing IP, Transport(TCP), Payloads with scapy.')
    parser.add_argument('-S', '-src', action='store', dest='src', default='127.0.0.1',
                        help='select file to read the fuzzing data')
    parser.add_argument('-D', '-dst', action='store', dest='dst', default='127.0.0.1',
                        help='select file to read the fuzzing data')
    parser.add_argument('-SP', '-sport', action='store', dest='sp', default='1337',
                        help='select file to read the fuzzing data')
    parser.add_argument('-DP', '-dport', action='store', dest='dp', default='1338',
                        help='select file to read the fuzzing data')
    parser.add_argument('-F', '-file', action='store', dest='file_name', default='default.csv',
                        help='select file to read the fuzzing data')
    parser.add_argument('-PF', '-payloadfile', action='store', dest='payload_file', default='default_payload.csv',
                        help='select file to read the default payload data')
    parser.add_argument('-I', '-ip', action='store_true', default=False,
                        help='run fuzzing for IP layer')
    parser.add_argument('-T', '-tcp', action='store_true', default=False,
                        help='run fuzzing for TCP layer')
    parser.add_argument('-P', '-payload', action='store_true', default=False,
                        help='run fuzzing for Payloads')
    parser.add_argument('-tA', '-tall', action='store_true', default=False,
                        help='run fuzzing for all fields for TCP layer')
    parser.add_argument('-iA', '-iall', action='store_true', default=False,
                        help='run fuzzing for all fields for IP layer')
    parser.add_argument('-v', '-verbose', action='store', default=0,
                        help='run fuzzing for Payloads')
    tcp_fields = (
        "seq",
        "ack",
        "dataofs",
        "reserved",
        "flags",
        "window",
        "chksum",
        "urgptr",
        "options"
    )
    for f in tcp_fields:
        parser.add_argument('-t' + f, action='append_const',
                            dest='tcp_field', const=f, default=[],
                            help='Add ' + f + ' to TCP fields for fuzzing')

    ip_fields = ("len", "proto", "ihl",
                 "flags", "frag",
                 "ttl")
    for f in ip_fields:
        parser.add_argument('-i' + f, action='append_const',
                            dest='ip_field', const=f, default=[],
                            help='Add ' + f + ' to IP fields for fuzzing')

    args = parser.parse_args()
    print(args)
    print(args.file_name)

    try:
        v = int(args.v)
    except ValueError:
        "Wrong verbosity value given"
        sys.exit()


    # payload = open(args.pay)

    if args.I:
        ipfuzz = IPFuzzer(source=args.src,dest=args.dst)
        ipfuzz.fuzz(fields=args.ip_field)
    if args.T:
        pass
    if args.P:
        pass