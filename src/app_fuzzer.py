from scapy.all import *

class APPFuzzer():
    def __int__(self,source,dest):
        self._pckt = IP(dst=dest,source=source)/TCP()

    def fuzz(self,test=0, size=None,file=None):
        pckts = []
        if not file:
            if not size:
                for _ in range(test):
                    pckts.append(self._pckt/raw())
            else:

        else: