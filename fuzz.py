from src.tcp_fuzzer import TCPFuzzer
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Fuzzing IP, Transport(TCP), Payloads with scapy.')
    parser.add_argument('-F', '--file', action='store', dest='file_name', default='default.csv',
                        help='select file to read the fuzzing data')
    parser.add_argument('-I', '--ip', action='store_true', default=False,
                        help='run fuzzing for IP layer')
    parser.add_argument('-T', '--tcp', action='store_true', default=False,
                        help='run fuzzing for TCP layer')
    parser.add_argument('-P', '--payload', action='store_true', default=False,
                        help='run fuzzing for Payloads')
    parser.add_argument('--sport', action='append_const', dest='tcp_field',
                        const='sport',
                        default=[],
                        help='Add sport to TCP fields to test')
    parser.add_argument('--dport', action='append_const', dest='tcp_field',
                        const='dport',
                        default=[],
                        help='Add dport to TCP fields to test')
    parser.add_argument('--seq', action='append_const', dest='tcp_field',
                        const='seq',
                        default=[],
                        help='Add seq to TCP fields to test')
    parser.add_argument('--ack', action='append_const', dest='tcp_field',
                        const='ack',
                        default=[],
                        help='Add ack to TCP fields to test')
    parser.add_argument('--dataofs', action='append_const', dest='tcp_field',
                        const='dataofs',
                        default=[],
                        help='Add dataofs to TCP fields to test')
    parser.add_argument('--reserved', action='append_const', dest='tcp_field',
                        const='reserved',
                        default=[],
                        help='Add reserved to TCP fields to test')


    args = parser.parse_args()
    print(args)
    print(args.file_name)
    print(args.accumulate(args.integers))
