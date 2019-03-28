###Setting up Client and Server

####Starting from two fresh Ubuntu 18.04 Virtual Machine,

1.in the virtual machine menu, set network adapter to "bridge to adapter."

####Execute the following commands

2.```sudo apt install python3```

3.```sudo apt install python3-pip```

4.```pip3 install scapy```

5.```pip3 install pandas```

6.```sudo apt install net-tools```

7.run ```sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP | sudo iptables -L```

before running client/server side programs to suppress RST flags.

####using net-tools, find the ipv4 address of the server VM.

8.run the server by ```sudo python3 run_server.py```

9.run the client by ```sudo python3 *src* *dst* *sport* *dport*```

10.if you type in the input after the prompt

```input packet to send: ```, type in any text and check the server end.

11.If your message appears with the appropriate valid/invalid message, success!

12.To quit, press Ctrl+V on the server side. input Q or q on the input prompt to exit on the client side.


#### Comments

1.the fuzzer uses scapy 2.4.2

2.Ubuntu 18.04
