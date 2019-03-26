# 4182_fuzzer


run iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP before running client/server side programs to suppress RST flags.