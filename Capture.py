from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, ARP
from scapy.layers.inet import TCP


class Device:
    """Default Class for Network Devices"""
    def __init__(self, mac):
        self.mac = None
        self.mac = mac
        self.ip = None
        self.oui = None
        self.frame_numbers = None

    def show(self):
        print("\n")
        print("Mac is: " + str(self.mac))
        print("IP is: " + str(self.ip))
        print("OUI is: " + str(self.oui))
        print("Frames Seen are: " + str(self.frame_numbers))

    def set_attribute(self, key, value):
        if getattr(self, key) == None:
            value = [value]
            setattr(self, key, value)
        else:
            att = getattr(self, key)
            att.append(value)
            setattr(self, key, att)

class Client(Device):
    """Device Class for Devices determined to be clients"""
    def __init__(self, mac):
        Device.__init__(self, mac)
        self.user_agent_string = None
        self.destination_ip = None
        self.uris = None
        self.os = None
        self.browser = None

    def show(self):
        print("\n")
        print("Mac is: " + str(self.mac))
        print("IP is: " + str(self.ip))
        print("OUI is: " + str(self.oui))
        print("User Agent String is: " + str(self.user_agent_string))
        print("Destination IP Addresses are: " + str(self.destination_ip))
        print("URIs include: " + str(self.uris))
        print("Operating System seems to be " + str(self.os))
        print("Browser seems to be: " + str(self.browser))
        print("Frames Seen are: " + str(self.frame_numbers))


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

    def show(self):
        print("\n")
        print("Mac is: " + str(self.mac))
        print("IP is: " + str(self.ip))
        print("OUI is: " + str(self.oui))
        print("SSID is: " + str(self.ssid))
        print("Mode is: " + str(self.mode))
        print("Channel is: " + str(self.channel))
        print("Encryption is: " + str(self.enc))
        print("Rates include: " + str(self.rates))
        print("Frames Seen are: " + str(self.frame_numbers))



cap = rdpcap("/root/Desktop/Small.pcap")

AccessPointDict = {}
ClientDict = {}
DeviceDict = {}


def process_beacon(num, packet):
    mac = packet[Dot11].addr2
    if mac in AccessPointDict:
        AccessPointDict[mac].frame_numbers.append(num)
    else:
        AccessPointDict[mac] = AccessPoint(mac)
        ap = AccessPointDict[mac]
        ap.set_attribute('frame_numbers', num)

        # set ssid
        lssid = packet[Dot11Beacon].payload.info.decode('utf-8')
        ap.set_attribute('ssid', lssid)

        # set channel
        channel = int.from_bytes(packet[4].info, byteorder='big')
        ap.channel = channel

        # find all rates and set rates
        ###Supported Rates
        rates_bytes = bytearray(packet[3].info)
        rates = []
        for i in rates_bytes:
            if i > 60:
                i -= 128
            rates.append(i / 2)
        ###Extended Supported Rates
        esrates_bytes = bytearray(packet[7].info)
        for i in esrates_bytes:
            rates.append(i / 2)
        ap.rates = rates

        # set the cypher and encrpytion
        arr = bytearray(packet[8].info)
        if arr[5] == 4:
            ap.cypher = "AES"
            ap.enc = "WPA2"
        elif arr[5] == 2:
            ap.cypher = "TKIP"
            ap.enc = "WPA"
        else:
            ap.cypher = "RCv4"
            ap.enc = "OPEN or WEP"

        # set mode
        if packet[15].ID == 192:
            ap.mode = 'AC'
        elif packet[10].ID == 45:
            ap.mode = 'N'
        elif ap.channel > 14:
            ap.mode = 'A'
        elif 54.0 in ap.rates:
            ap.mode = 'G'
        else:
            ap.mode = 'B'


def process_arp(num, packet):
    hwmac = packet[ARP].hwsrc
    dev = find_device(hwmac)
    op = packet[ARP].op
    ip = packet[ARP].psrc
    if op == 2:
        dev.set_attribute('ip', ip)
    dev.set_attribute('frame_numbers', num)
    dstmac = packet[ARP].hwdst
    otherdev = find_device(dstmac)
    dstip = packet[ARP].pdst
    otherdev.ip = dstip
    otherdev.set_attribute('frame_numbers', num)


def process_http(num, packet):
    mac = packet[Dot11].addr2
    dev = find_device(mac)

    load = packet[6].load
    load_list = load.decode('utf-8').split('\n')
    print(load_list)
    for i in load_list:
        if 'User-Agent' in i:
            print(i[12:])
        elif 'Host' in i:
            print(i[6:])
        elif 'Referer' in i:
            print(i[9:])


def find_device(mac):
    if mac in AccessPointDict:
        dev = AccessPointDict[mac]
    elif mac in ClientDict:
        dev = ClientDict[mac]
    elif mac in DeviceDict:
        dev = DeviceDict[mac]
    else:
        DeviceDict[mac] = Device(mac)
        dev = DeviceDict[mac]
    return dev


# TODO take in a default device type and have it return that instead of just device

packet_num = 0
for packet in cap:
    packet_num += 1
    if Dot11Beacon in packet:
        process_beacon(packet_num, packet)
    elif ARP in packet:
        process_arp(packet_num, packet)
    elif TCP in packet:
        if packet[TCP].dport == 80:
            packet.show()
