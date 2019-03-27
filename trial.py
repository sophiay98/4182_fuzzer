from scapy.all import *


class APPFuzzer():
    def __init__(self,source="127.0.0.1", dest="127.0.0.1",dport="80"):
        self._dest = dest
        self._pckt = Ether()/IP(dst=dest,src=source)/TCP(dport=dport)

    def _get_payload(self,addr):
        pckts = []
        try:
            f = open(addr, "r")
            payloads = f.readlines()
            if len(payloads) < 1:
                print("there's nothing in the file")
                print("terminating...")
                return pckts
            #if value in the file is not hex string
            for payload in payloads:
                try:
                    p = bytes.fromhex(payload)  # only reads the first line of the file
                    print("using payload: 0x" + payload)
                    pckts.append(self._pckt / p)
                except ValueError:
                    print("%s cannot be parsed as hex" % (payload))
                    print("continue parsing the remaining of the file %s ..."%(addr))
        except IOError:
            print("cannot open file: %s" %(addr))
            print("terminating...")
        return pckts

    def _rand_payload(self,test=0,size=None,min_len=2,max_len=128):
        pckts = []
        if size:
            size=size*2
        for _ in range(test):
            length=size
            if not size:
                length = random.randint(min_len, max_len)*2
            payload = ''.join(
                random.choice(list(chr(_) for _ in range(ord('a'), ord('f') + 1)) + list(str(_) for _ in range(10))) for _ in
                range(length))
            pckts.append(self._pckt / bytes.fromhex(payload))
        return pckts

    def fuzz(self,test=0, size=None,file=None,min_len=0,max_len=128):
        if file:
            pckts = self._get_payload("./" + file)
        else:
            pckts = self._rand_payload(test,size,min_len,max_len)

        valid = 0
        tot = len(pckts)
        print("sending packets to the server...")
        filter = "ip host %s"%(self._dest)
        sniff(filter=filter,count=tot)
        for pckt in pckts:
            sendp(pckt)
        print("finished sending")
        print("%d packets are sent" % tot)
        print("valid: %d" % valid)
        print("invalid: %d" %(tot-valid))


fuzz = APPFuzzer("127.0.0.1","10.0.2.15",1338)
fuzz.fuzz(test=3,min_len=2,max_len=4)