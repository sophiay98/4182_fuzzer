from scapy.all import *
from .client import Client

class APPFuzzer():
    def __init__(self,source="127.0.0.1", dest="127.0.0.1", sport=1337, dport=1338, verbose=0):
        self._pckt = Ether()/IP(dst=dest,src=source)/TCP()
        self.client = Client(source,dest,sport,dport,verbose=verbose)
        self.verbose = verbose

    #read in payloads
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
                    pckts.append(p)
                # if cannot be interpreted as hex string
                except ValueError:
                    print("\"%s\" cannot be parsed as hex" % (payload))
                    print("continue parsing the remaining of the file %s ..."%(addr))
        except IOError:
            print("cannot open file: %s" %(addr))
            print("terminating...")
        return pckts

    #generate payloads
    def _rand_payload(self,test=0,size=None,min_len=2,max_len=128):
        pckts = []
        if size:
            #2-digit hex string is 1 byte thus *2
            size=size*2

        for _ in range(test):
            #if fixed size
            length=size
            #if varied size.
            if not size:
                length = random.randint(min_len, max_len)*2 #2-digit hex string is 1 byte thus *2
            #generate each digit by randomly choosing from 0–9 and a-f
            payload = ''.join(
                random.choice(list(chr(_) for _ in range(ord('a'), ord('f') + 1)) + list(str(_)
                                        for _ in range(10))) for _ in range(length))
            pckts.append(bytes.fromhex(payload))
        return pckts

    def fuzz(self,test=0, size=None,file=None,min_len=1,max_len=128):
        if file:
            #try reading in from file
            try:
                pckts = self._get_payload("./" + str(file))
            except IOError:
                print("file not found")
                pckts = self._rand_payload(test, size, min_len, max_len)
        else:
            #generate random payloads with given length parameters
            pckts = self._rand_payload(test,size,min_len,max_len)

        print("sending packets to the server...")
        self.client.connect()
        for pckt in pckts:
            try:
                self.client.send(pckt)
                time.sleep(2)
            except OSError as err:
                print(err)
                print()
                print("an error occurred while sending packets.")
                print("is the length of the packets under 3000?")
                print("terminating the program...")
                return
        print("finished sending")

        print("total count: " + str(self.client.total))
        print("valid count: " + str(self.client.valid))
        print("invalid count: " + str(max(0,self.client.invalid)))


if __name__ == "__main__":
    fuzz = APPFuzzer("127.0.0.1","127.0.0.1")
    fuzz.fuzz(test=3,min_len=2,max_len=4)