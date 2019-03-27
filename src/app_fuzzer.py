from scapy.all import *

class APPFuzzer():
    def __int__(self,source,dest,addr=None):
        self._pckt = Ether()/IP(dst=dest,source=source)/TCP()

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
        for _ in range(test):
            length=size
            if not size:
                length = random.randint(min_len, max_len)*2
            payload = ''.join(
                random.choice(list(chr(_) for _ in range(ord('a'), ord('f') + 1)) + list(range(10))) for _ in
                range(length))
            pckts.append(self._pckt / bytes.fromhex(payload))
        return pckts

    def fuzz(self,test=0, size=None,file=None,min_len=2,max_len=128):
        if file:
            pckts = self._get_payload("./" + file)
        else:
            pckts = self._rand_payload(test,size,min_len,max_len)



