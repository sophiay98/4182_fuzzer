# 4182_fuzzer

###Usage
####IP Layer Fuzzer

The ip layer fuzzer is able to run two kinds of tests:

#####1.default tests
to run this test:

    sudo python3 fuzz.py -I (-i[FIELD])*
    

f is a list of fields name.

valid values for items in FIELD are:

    ttl,len,proto,ihl,flags,frag,tos,id,chksum,version
    
example:
    
    sudo python3 fuzz.py -I -ttl

If f is not specified or f = None, all fields will be fuzzed.
#####2.reading from a csv file
to run this test:

    sudo python3 fuzz.py -I -ifile [file_name] -v 1

file_name is the name of the file at the current directory.

First row the file indicate the name of the field corresponding to the values in each column.

Valid values for the first row are:


    ttl,len,proto,ihl,flags,frag,tos,id,chksum,version



To skip fuzzing a field, simply leave the cell corresponding to that field empty.

The value of each cell should be a hex string in the format of 0x00 within the range of the valid values for that field.

For example, a valid CSV file shoud look like:


    ttl,len,version
    0x11,0xf00f,0xf
    0x01,,0xf

Each row will produce one packet to be sent.

#####3 Payload
A default payload is included for each packet sent.

The default payload is read in from ```./payload``` file.

The user can edit the file with values desired. However, the value should be a hex string(with no prefix such as 0x) and be on the first line of the file.
Else the content of the file will be erased and recovered with the default value 00.

The length of the payload should not exceed the upper limit set by Scapy. We recommend it to be length then 3000 bytes.

####TCP Layer Fuzzer

The tcp layer fuzzer is able to run three kinds of tests:

#####1.default tests
to run this test:

    
    sudo python3 fuzz.py -T (-t[FIELD])*
    

FIELD indicates the field to fuzz.
it will then generate a packet for every possible value for that field.

valid values for items in FIELD are:


    sport, dport, seq, ack, dataofs, reserved, flags, window, chksum, urgptr,options

If FIELD is not specified or seq field will be fuzzed.

#####2.reading from a csv file
to run this test:

    sudo python3 fuzz.py -T -tfile [*file_name*] -v 1

file_name is the name of the file at the current directory.

First row the file indicate the name of the field corresponding to the values in each column.

Valid values for the first row are:


    sport, dport, seq, ack, dataofs, reserved, flags, window, chksum, urgptr,options



To skip fuzzing a field, simply leave the cell corresponding to that field empty.

The value of each cell should be a hex string within the range of the valid values for that field in the format of 0x00.

For example, a valid CSV file should look like:


    seq,flags,chksum
    0x01,0x00,0x02
    0x02,0x01,0x01


Each row will produce one packet to be sent.

#####3 Payload
A default payload is included for each packet sent.

The default payload is read in from ```./payload``` file.

The user can edit the file with values desired. However, the value should be a hex string(with no prefix such as 0x) and be on the first line of the file.
Else the content of the file will be erased and recovered with the default value 00.

The length of the payload should not exceed the upper limit set by Scapy. We recommend it to be length then 3000 bytes.

####Application Layer Fuzzer

The ip layer fuzzer is able to run three kinds of tests:

#####1.default tests with varied payload length
to run this test:

    
    sudo python3 fuzz.py -A [-amin MIN] [-amax MAX] [-N N]
    
it send a given number of packets with payload of varied lengths within a given range

-N N field sets the number of tests to run. It has to be a positive integer.
-amin MIN sets the minimum length in byte of the payload. It has to be a positive integer as well.
-amax MAX sets the maximum length in byte of the payload. It has to be greater than or equal to min_len and has to be less then the payload limit indicated by Scapy ( e.g. we recommend it to be less than 3000)

#####2.default test with fixed payload length
to run this test:

    
    sudo python3 fuzz.py -A [-L LEN] [-N N]
    
it send a given number of packets with payload of length.

-N N field sets the number of tests to run. It has to be a positive integer.

-L LEN sets the  length in byte of the payload. It has to be a positive integer and less then the payload limit indicated by Scapy ( e.g. we recommend it to be less than 3000)

#####3.reading from a file
to run this test:

    
    sudo python3 fuzz.py -A -afile file_name [-N N]

file_name is the name of the file at the current directory.

-N N field sets the number of tests to run. It has to be a positive integer.

Each row of the file contains one payload that is no greater than the largest payload Scapy can take.

The payload should be hex strings with no prefixes such as 0x or x/. It should not be an empty string and should not have a length logner then 3000.


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

10.set the default accepting payload on src/pattern.

11.the server reads pattern.txt to obtain accepting payload pattern. If pattern.txt is not found, it will fall back to \x00 for accepting pattern.
####optional arguments comments
1.The optional arguments are not exclusive. You can run IP layer fuzzing with TCP layer fuzzing with one call, by passing -I and -T through optional arguments.

2.You can pass in -A to test all fields. (while not reading in from a file)

3.However, there are precedence
2. if there is an 'all' argument, it will test all fields randomly, disregarding filename argument.
2. if there is a filename argument, the fuzzer will only test on the file, ignoring the field values for randomly generating tests.

4.The arguments can be shortened within an argument

ex)```sudo python3 fuzz.py -TA```

5.sample execution: ```sudo python3 fuzz.py -src 192.168.1.13 -dst 192.168.1.11 -sport 1337 -dport 1338 -A -v 0 -N 10```

6.below is --help for the fuzz.py

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
