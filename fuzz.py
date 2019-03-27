from src.tcp_fuzzer import TCPFuzzer
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Fuzzing IP, Transport(TCP), Payloads with scapy.')
    parser.add_argument('-F', '-file', action='store', dest='file_name', default='default.csv',
                        help='select file to read the fuzzing data')
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

    tcp_fields = (
        "sport",
        "dport",
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
