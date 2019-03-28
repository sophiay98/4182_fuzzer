# 4182_fuzzer

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

###Usage
####IP Layer Fuzzer

The ip layer fuzzer is able to run two kinds of tests:

#####1.default tests
to run this test:

    ipfuzzer = IPFuzzer(source=source, dest=dest)
    ipfuzzer.fuzz(field=f)
    

f is a list of fields name.

valid values for items in f are:


    ttl,len,proto,ihl,flags,frag,tos,id,chksum,version

If f is not specified or f = None, all fields will be fuzzed.
#####2.reading from a csv file
to run this test:

    ipfuzzer = IPFuzzer(source=source, dest=dest,sport=sport, dport=dport)
    ipfuzzer.fuzz(file=file_name)

file_name is the name of the file at the current directory.

First row the file indicate the name of the field corresponding to the values in each column.

Valid values for the first row are:


    ttl,len,proto,ihl,flags,frag,tos,id,chksum,version



To skip fuzzing a field, simply leave the cell corresponding to that field empty.

The value of each cell should be a hex string within the range of the valid values for that field.

For example, a valid CSV file should look like:


    ttl,len,version
    0x11,0xf00f,0xf
    0x01,,0xf

#####3 Payload
A default payload is included for each packet sent.

The default payload is read in from ```./payload``` file.

The user can edit the file with values desired. However, the value should be a hex string(with no prefix such as 0x) and be on the first line of the file.
Else the content of the file will be erased and recovered with the default value 00.

####TCP Layer Fuzzer

The tcp layer fuzzer is able to run three kinds of tests:

#####1.default tests on specific fields
to run this test:

    
    tcpfuzzer = TCPFuzzer(source=source, dest=dest,sport=sport, dport=dport)
    ipfuzzer.fuzz(field=f)
    

f is a field name.
it will then generate a packet for every possible value for that field.

valid values for f are:


    seq, ack, dataofs, reserved, flags, window, chksum, urgptr,options

#####2 default tests on all fields
to run this, simply run :

    
    tcpfuzzer = TCPFuzzer(source=source, dest=dest,sport=sport, dport=dport)
    ipfuzzer.fuzz(all=True)
    

#####3.reading from a csv file
to run this test:

    tcpfuzzer = TCPFuzzer(source=source, dest=dest,sport=sport, dport=dport)
    tcpfuzzer.fuzz(file=file_name)

file_name is the name of the file at the current directory.

First row the file indicate the name of the field corresponding to the values in each column.

Valid values for the first row are:


      seq, ack, dataofs, reserved, flags, window, chksum, urgptr,options



To skip fuzzing a field, simply leave the cell corresponding to that field empty.

The value of each cell should be a hex string within the range of the valid values for that field.

For example, a valid CSV file shoud look like:


    seq, ack, dataofs
    0x11,0x00,0xf
    0x01,,0xf

#####3 Payload
A default payload is included for each packet sent.

The default payload is read in from ```./payload``` file.

The user can edit the file with values desired. However, the value should be a hex string(with no prefix such as 0x) and be on the first line of the file.
Else the content of the file will be erased and recovered with the default value 00.


####Application Layer Fuzzer

The application layer fuzzer is able to run two kinds of tests:

#####1 payload with varied length
it send a given number of packets with payload of varied lengths within a given range

to run this test:

    
    appfuzzer = APPFuzzer(source=src, dest=dest, sport=sport, dport=dport)
    appfuzzer.fuzz(test=num, min_len=min,max_len=max)
    

test field sets the number of tests to run. It should be a positive integer.
min_len sets the minimum length in byte of the payload. It should be a positive integer as well.
max_len sets the maximum length in byte of the payload. It should be greater than or equal to min_len and should be less then the payload limit indicated by Scapy ( e.g. should be less then 3000)
 

#####2.reading from a csv file
to run this test:

    
    appfuzzer = APPFuzzer(source=src, dest=dest, sport=sport, dport=dport)
    appfuzzer.fuzz(file=filename)

file_name is the name of the file at the current directory.

Each row of the file contains one payload that is no greater than the largest payload Scapy can take.

The payload should be hex strings with no prefixes such as 0x or x/