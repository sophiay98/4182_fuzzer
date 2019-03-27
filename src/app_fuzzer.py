from scapy.all import *

class APPFuzzer():
    def __int__(self,source,dest):
        self._pckt = Ether()/IP(dst=dest,source=source)/TCP()

    def _get_payload(self,addr):
        pckts = []
        try:
            f = open(addr,"r")
            paylaods = f.readlines()
            if len(paylaods) < 1:
                raise IOError
            f.close()
            for payload in paylaods:
                pckts.append(self._pckt / payload)
        except IOError:
            self._rand_payload(test=50)

    def _rand_payload(self,test=0,size=None,min_len=2,max_len=128):
        pckts = []
        payload_base = '0x'  # 2 bytes
        for _ in range(test):
            length=size
            if not size:
                length = random.randint(min_len - 2, max_len - 2)
            payload_to_append = ''.join(
                random.choice(list(chr(_) for _ in range(ord('a'), ord('f') + 1)) + list(range(10))) for _ in
                range(length))
            payload = payload_base + payload_to_append
            pckts.append(self._pckt / payload)
        return pckts

    def fuzz(self,test=0, size=None,file=None,min_len=2,max_len=128):

        if file:
            pckts = self._get_payload("./" + file)
        else:
            pckts = self._rand_payload(test,size,min_len,max_len)



