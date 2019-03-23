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

    args = parser.parse_args()
    print(args)
    print(args.file_name)
    print(args.accumulate(args.integers))
