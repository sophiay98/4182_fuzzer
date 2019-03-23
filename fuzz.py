from src.tcp_fuzzer import TCPFuzzer
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Fuzzing IP, Transport(TCP), Payloads with scapy.')
    parser.add_argument('integers', metavar='N', type=int, nargs='+',
                        help='an integer for the accumulator')
    parser.add_argument('--tcp', dest='accumulate', action='store_const',
                        const=sum, default=max,
                        help='run fuzzing for tcp layer')
    parser.add_argument('--file', action='store', dest='file_name', default='default.csv')
    args = parser.parse_args()
    print(args.accumulate(args.integers))
