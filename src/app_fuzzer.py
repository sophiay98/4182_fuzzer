from scapy.all import *
from .client import Client

class APPFuzzer():
    def __init__(self,source="127.0.0.1", dest="127.0.0.1", sport=1337, dport=1338, verbose=0):
        self._pckt = Ether()/IP(dst=dest,src=source)/TCP()
        self.client = Client(source,dest,sport,dport,verbose=verbose)
        self.verbose = verbose

    def _get_payload(self,addr):
        pckts = []
        try:
            f = open(addr, "r")
            payloads = f.readlines()

            if len(payloads) < 1:
                print("there's nothing in the file")
                print("terminating...")
                return pckts

            #if contains payloads
            for payload in payloads:
                try:
                    p = bytes.fromhex(payload)  # only reads the first line of the file
                    print("using payload: 0x" + payload)
                    pckts.append(self._pckt/p)
                # if cannot be interpreted as hex string
                except ValueError:
                    print("\"%s\" cannot be parsed as hex" % (payload))
                    print("continue parsing the remaining of the file %s ..."%(addr))
        except IOError:
            print("cannot open file: %s" %(addr))
            print("terminating...")
        return pckts

    def _rand_payload(self,test=0,size=None,min_len=2,max_len=128):
        pckts = []
        if size:
            #2-digit hex string is 1 byte thus *2
            size=size*2
        for _ in range(test):
            length=size
            if not size:
                length = random.randint(min_len, max_len)*2
            payload = ''.join(
                random.choice(list(chr(_) for _ in range(ord('a'), ord('f') + 1)) + list(str(_)
                                        for _ in range(10))) for _ in range(length))
            pckts.append(self._pckt/bytes.fromhex(payload))
        return pckts

    def fuzz(self,test=0, size=None,file=None,min_len=1,max_len=128):
        if file:
            try:
                pckts = self._get_payload("./" + str(file))
            except IOError:
                print("file not found")
                pckts = self._rand_payload(test, size, min_len, max_len)
        else:
            pckts = self._rand_payload(test,size,min_len,max_len)

        print("sending packets to the server...")
        self.client.connect()
        for pckt in pckts:
            self.client.send(pckt)
        print("finished sending")

        print("total count: " + str(self.client.total))
        print("valid count: " + str(self.client.valid))
        # minus 4 for disregarding establishing/closing connection
        print("invalid count: " + str(max(0,self.client.invalid-4)))


if __name__ == "__main__":
    fuzz = APPFuzzer("127.0.0.1","127.0.0.1")
    fuzz.fuzz(test=3,min_len=2,max_len=4)