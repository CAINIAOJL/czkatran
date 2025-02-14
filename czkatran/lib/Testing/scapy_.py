from scapy.all import *
from scapy.layers.inet import *


def main():
    pkt = IP(dst="10.0.0.1")/TCP(dport=80)
    send(pkt, verbose=False)    # send(pkt)