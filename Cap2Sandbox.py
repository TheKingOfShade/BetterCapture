from scapy.all import *
from scapy.layers import *

cap = rdpcap("/root/Desktop/pcaps/ACBeacon.pcap")
for packet in cap:
    packet[10].show()