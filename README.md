# 4182_fuzzer


run iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP before running client/server side programs to suppress RST flags.
run iptables -L
after each connection, run sysctl -w net.ipv4.tcp_timestamps=0 to reset connection status.