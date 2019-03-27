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

9.If your message appears with the appropriate valid/invalid message, success!

10.To quit, press Ctrl+V on the server side. input Q or q on the input prompt to exit on the client side.

####Server Comments
1.server can receive up to 128 bytes of payload at a time. Any payload longer than that will be sliced after reaching 128 bytes.

2.Since the server's response only has to contain 0x00 or 0xff for each payload sent, the actual response is "0x00" * 4 and "0xff" * 4, respectively.

3.The server does __not__ accept empty payloads.

4.issues may arise because of the firewall & RTS flags that gets automatically generated during establishing TCP connection with the server.

5.the server only allows one connection at a time. There __cannot__ be multiple fuzzing running at the same time. Server will not respond while there is already another established connection.

6.When opening a new server, __wait__ until the message ```listening on port ***``` appears. Until then the port is either closed or in use.