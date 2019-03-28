###Setting up Client and Server

####Starting from two fresh Ubuntu 18.04 Virtual Machine,

1.in the virtual machine menu, set network adapter to "bridge to adapter."

####Execute the following commands

2.```sudo apt install python3```

3.```sudo apt install python-pip```

4.```pip3 install scapy```

5.```pip3 install pandas``

6.```sudo apt install net-tools```

7.run 
```sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP | sudo iptables -L```

before running client/server side programs to suppress RST flags.

####using net-tools, find the ipv4 address of the server VM.

8.run the server by ```sudo python3 run_server.py```

9.run the client by ```sudo python3 *src* *dst* *sport* *dport*```

10.if you type in the input after the prompt

```input packet to send: ```, type in any text and check the server end.

11.If your message appears with the appropriate valid/invalid message, success!

12.To quit, press Ctrl+V on the server side. input Q or q on the input prompt to exit on the client side.

####Server Comments
1.server can receive up to 128 bytes of payload at a time. Any payload longer than that will be sliced after reaching 128 bytes.

2.Since the server's response only has to contain 0x00 or 0xff for each payload sent, the actual response is "0x00" * 4 and "0xff" * 4, respectively.

3.The server does __not__ accept empty payloads.

4.issues may arise because of the firewall & RTS flags that gets automatically generated during establishing TCP connection with the server.

5.the server only allows one connection at a time. There __cannot__ be multiple fuzzing running at the same time. Server will not respond while there is already another established connection.

6.the server can handle only one connection per execution. restart the server to try new fuzzing for the application layer.

7.When opening a new server, __wait__ until the message ```listening on port ***``` appears. Until then the port is either closed or in use.

8.The tests were only done within an internal address environment (VM to VM). Other circumstances (ex. Connecting to server through the external IP address) would work with some modifications, but it is not guaranteed.

9.The application layer testing can be very slow. (~2 seconds per input)
####optional arguments comments
1.The optional arguments are not exclusive. You can run IP layer fuzzing with TCP layer fuzzing with one call, by passing -I and -T through optional arguments.

2.You can pass in -A to test all fields. (while not reading in from a file)

3.However, there are precedence
2. if there is an 'all' argument, it will test all fields randomly, disregarding filename argument.
2. if there is a filename argument, the fuzzer will only test on the file, ignoring the field values for randomly generating tests.

4.sample execution: ```sudo python3 fuzz.py -src 192.168.1.13 -dst 192.168.1.11 -sport 1337 -dport 1338 -A -v 0 -N 10```

4.below is --help for the fuzz.py

```
usage: fuzz.py [-h] [-S SRC] [-D DST] [-SP SP] [-DP DP] [-IF IFILE_NAME]
               [-TF TFILE_NAME] [-AF AFILE_NAME] [-PF PAYLOAD_FILE] [-I] [-T]
               [-A] [-tA] [-iA] [-N N] [-v V] [-amin AMIN] [-amax AMAX]
               [-L LEN] [-tseq] [-tack] [-tdataofs] [-treserved] [-tflags]
               [-twindow] [-tchksum] [-turgptr] [-toptions] [-ilen] [-iproto]
               [-iihl] [-iflags] [-ifrag] [-ittl] [-itos] [-iid] [-ichksum]
               [-iversion]

Fuzzing IP, Transport(TCP), Payloads with scapy.

optional arguments:
  -h, --help            show this help message and exit
  -S SRC, -src SRC      select source ip address
  -D DST, -dst DST      select destination ip address
  -SP SP, -sport SP     select source port
  -DP DP, -dport DP     select destination port
  -IF IFILE_NAME, -ifile IFILE_NAME
                        select file to read the fuzzing data for ip layer
  -TF TFILE_NAME, -tfile TFILE_NAME
                        select file to read the fuzzing data for tcp layer
  -AF AFILE_NAME, -afile AFILE_NAME
                        select file to read the fuzzing data for application
                        layer
  -PF PAYLOAD_FILE, -payloadfile PAYLOAD_FILE
                        select file to read the default payload data
  -I, -ip               run fuzzing for IP layer
  -T, -tcp              run fuzzing for TCP layer
  -A, -app              run fuzzing for application layer
  -tA, -tall            run fuzzing for all fields for TCP layer
  -iA, -iall            run fuzzing for all fields for IP layer
  -N N, -num N          number of tests to run
  -v V, -verbose V      set verbosity level
  -amin AMIN            minimum length for payload
  -amax AMAX            maximum length for payload
  -L LEN, -len LEN      length of the payload
  -tseq                 Add seq to TCP fields for fuzzing
  -tack                 Add ack to TCP fields for fuzzing
  -tdataofs             Add dataofs to TCP fields for fuzzing
  -treserved            Add reserved to TCP fields for fuzzing
  -tflags               Add flags to TCP fields for fuzzing
  -twindow              Add window to TCP fields for fuzzing
  -tchksum              Add chksum to TCP fields for fuzzing
  -turgptr              Add urgptr to TCP fields for fuzzing
  -toptions             Add options to TCP fields for fuzzing
  -ilen                 Add len to IP fields for fuzzing
  -iproto               Add proto to IP fields for fuzzing
  -iihl                 Add ihl to IP fields for fuzzing
  -iflags               Add flags to IP fields for fuzzing
  -ifrag                Add frag to IP fields for fuzzing
  -ittl                 Add ttl to IP fields for fuzzing
  -itos                 Add tos to IP fields for fuzzing
  -iid                  Add id to IP fields for fuzzing
  -ichksum              Add chksum to IP fields for fuzzing
  -iversion             Add version to IP fields for fuzzing

```
note that the above list might be slightly different from what is actually printed when calling --help.
