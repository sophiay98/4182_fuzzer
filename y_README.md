###Setting up Client and Server

####Starting from two fresh Ubuntu 18.04 Virtual Machine,

1.in the virtual machine menu, set network adapter to "bridge to adapter."

####Execute the following commands

2.```sudo apt install python3```

3.```sudo apt install python-pip```

4.```sudo apt install scapy```

5.```sudo apt install net-tools```

6.run 
```sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP | sudo iptables -L```

before running client/server side programs to suppress RST flags.

####using net-tools, find the ipv4 address of the server VM.

6.run the server by ```sudo python3 run_server.py```

7.run the client by ```sudo python3 *src* *dst* *sport* *dport*```

8.if you type in the input after the prompt

```input packet to send: ```, type in any text and check the server end.

If your message appears with the appropriate valid/invalid message, success!