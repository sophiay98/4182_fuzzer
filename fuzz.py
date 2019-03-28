import sys

from src.tcp_fuzzer import TCPFuzzer
from src.ip_fuzzer import IPFuzzer
from src.app_fuzzer import APPFuzzer
import argparse

if __name__ == "__main__":

    # add argument parsing criteria
    parser = argparse.ArgumentParser(description='Fuzzing IP, Transport(TCP), Payloads with scapy.')
    parser.add_argument('-S', '-src', action='store', dest='src', default='127.0.0.1',
                        help='select source ip address')
    parser.add_argument('-D', '-dst', action='store', dest='dst', default='127.0.0.1',
                        help='select destination ip address')
    parser.add_argument('-SP', '-sport', action='store', dest='sp', default='1337',
                        help='select source port')
    parser.add_argument('-DP', '-dport', action='store', dest='dp', default='1338',
                        help='select destination port')
    parser.add_argument('-IF', '-ifile', action='store', dest='Ifile_name', default=None,
                        help='select file to read the fuzzing data for ip layer')
    parser.add_argument('-TF', '-tfile', action='store', dest='Tfile_name', default=None,
                        help='select file to read the fuzzing data for tcp layer')
    parser.add_argument('-AF', '-afile', action='store', dest='Afile_name', default=None,
                        help='select file to read the fuzzing data for application layer')
    parser.add_argument('-PF', '-payloadfile', action='store', dest='payload_file', default='default_payload',
                        help='select file to read the default payload data')
    parser.add_argument('-I', '-ip', action='store_true', default=False,
                        help='run fuzzing for IP layer')
    parser.add_argument('-T', '-tcp', action='store_true', default=False,
                        help='run fuzzing for TCP layer')
    parser.add_argument('-A', '-app', action='store_true', default=False,
                        help='run fuzzing for application layer')
    parser.add_argument('-tA', '-tall', action='store_true', default=False,
                        help='run fuzzing for all fields for TCP layer')
    parser.add_argument('-iA', '-iall', action='store_true', default=False,
                        help='run fuzzing for all fields for IP layer')
    parser.add_argument('-N', '-num', action='store', default=100,
                        help='number of tests to run')
    parser.add_argument('-v', '-verbose', action='store', default=0,
                        help='set verbosity level')
    parser.add_argument('-amin', action='store', dest='amin', default=1,
                        help='minimum length for payload')
    parser.add_argument('-amax', action='store', dest='amax', default=128,
                        help='maximum length for payload')
    parser.add_argument('-L', "-len", action='store', dest='len', default=128,
                        help='length of the payload')

    #add tcp fields options
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

    #add ip fields options
    ip_fields = ("len", "proto", "ihl",
                 "flags", "frag",
                 "ttl", "tos",
                 "id",
                 "chksum",
                 "version")
    for f in ip_fields:
        parser.add_argument('-i' + f, action='append_const',
                            dest='ip_field', const=f, default=[],
                            help='Add ' + f + ' to IP fields for fuzzing')

    args = parser.parse_args()
    # print(args)

    # convert integer strings to int
    try:
        v = int(args.v)
        sp = int(args.sp)
        dp = int(args.dp)
        N = int(args.N)
        amin = int(args.amin)
        amax = int(args.amax)
        len = int(args.len)
    except ValueError:
        "Wrong integer value given for fields expected to have integer values."
        sys.exit()

    # value asserting
    int_values = (v, sp, dp, N, amin, amax, len)
    for i in int_values:
        if i < 0:
            print("All possible integer optional arguments has to be positive.")
            sys.exit()

    # run fuzzing
    if args.I:
        ipfuzz = IPFuzzer(source=args.src, dest=args.dst, payload=args.payload_file, verbose=args.v)
        if not args.iA and not args.Ifile_name:
            ipfuzz.fuzz(fields=args.ip_field)
        elif args.iA:
            ipfuzz.fuzz(all=True)
        elif args.Ifile_name:
            ipfuzz.fuzz(file=args.Ifile_name)
    if args.T:
        tcpfuzz = TCPFuzzer(source=args.src, dest=args.dst, sport=sp, dport=dp, payload=args.payload_file,
                            verbose=args.v)
        if not args.tA and not args.Tfile_name:
            for field in args.tcp_field:
                tcpfuzz.fuzz(field)
        elif args.tA:
            tcpfuzz.fuzz(all=True,num_trials=N)
        elif args.Tfile_name:
            tcpfuzz.fuzz(file=args.Tfile_name)
    if args.A:
        appfuzz = APPFuzzer(source=args.src, dest=args.dst, sport=sp, dport=dp, verbose=v)
        if args.Afile_name:
            appfuzz.fuzz(test=N, size=len, file=args.Afile_name, min_len=amin, max_len=amax)
        else:
            appfuzz.fuzz(test=N, size=len, min_len=amin, max_len=amax)
