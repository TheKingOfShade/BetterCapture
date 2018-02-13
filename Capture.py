from scapy.all import *
from scapy.layers import *



class Device:
    """Default Class for Network Devices"""
    def __init__(self, mac):
        self.mac = mac
        self.ip = None
        self.oui = None


class Client(Device):
    """Device Class for Devices determined to be clients"""
    def __init__(self, mac):
        Device.__init__(self, mac)
        self.user_agent_string = None
        self.destination_ip = None
        self.uris = None
        self.os = None
        self.browser = None


class AccessPoint(Device):
    """Device Class for devices determined to be Access Points"""
    def __init__(self, mac):
        Device.__init__(self, mac)
        self.ssid = None
        self.mode = None
        self.channel = None
        self.enc = None
        self.rates = None
        self.cypher = None


    def set_mode(self):
        pass

cap = rdpcap("/root/Desktop/Small.pcap")

AccessPointDict = {}

for packet in cap:
    if Dot11Beacon in packet:
        mac = packet[Dot11].addr2
        AccessPointDict[mac] = AccessPoint(mac)
        ap = AccessPointDict[mac]

        #set ssid
        ssid = packet[Dot11Beacon].payload.info.decode('utf-8')
        ap.ssid = ssid

        #set channel
        channel = int.from_bytes(packet[4].info, byteorder='big')
        print(channel)
        ap.channel = channel

        #find all rates and set rates
        rates_bytes = bytearray(packet[3].info)
        rates = []
        for i in rates_bytes:
            if i > 60:
                i -= 128
            rates.append(i/2)
        esrates_bytes = bytearray(packet[7].info)
        for i in esrates_bytes:
            rates.append(i/2)
        ap.rates = rates

        #set the cypher
        arr = bytearray(packet[8].info)
        if arr[5] == 4:
            cypher = "AES"
        elif arr[5] == 2:
            cypher = "TKIP"
        else:
            cypher = "RCv4"
        ap.cypher = cypher

        #mode check
        if packet[15].ID == 192:
            ap.mode == 'AC'
        elif packet[10].ID == 45:
            ap.mode == 'N'
