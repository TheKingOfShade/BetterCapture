from httpagentparser import *
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, ARP
from scapy.layers.inet import TCP, IP


class Device:
    """Default Class for Network Devices"""

    def __init__(self, mac):
        self.mac = None
        self.mac = mac
        self.ip = None
        self.oui = get_oui(mac)
        self.frame_numbers = None

    def show(self):
        print("\n")
        print("Mac is: " + str(self.mac))
        print("IP is: " + str(self.ip))
        print("OUI is: " + str(self.oui))
        print("Frames Seen are: " + str(self.frame_numbers))

    def set_attribute(self, key, value):
        if getattr(self, key) is None:
            value = [value]
            setattr(self, key, value)
        else:
            att = getattr(self, key)
            if value not in att:
                att.append(value)
                setattr(self, key, att)


class Client(Device):
    """Device Class for Devices determined to be clients"""

    def __init__(self, mac):
        Device.__init__(self, mac)
        self.user_agent_string = None
        self.networks = None
        self.destination_ip = None
        self.uris = None
        self.os = None
        self.browser = None
        self.rhosts = None
        self.referers = None

    def show(self):
        print("\n")
        print("Mac is: " + str(self.mac))
        print("IP is: " + str(self.ip))
        print("OUI is: " + str(self.oui))
        print("Networks this client is associated with: " + str(self.networks))
        print("User Agent String is: " + str(self.user_agent_string))
        print("Destination IP Addresses are: " + str(self.destination_ip))
        print("URIs include: " + str(self.uris))
        print("Operating System seems to be " + str(self.os))
        print("Browser seems to be: " + str(self.browser))
        print("Remote Hosts connected to are: " + str(self.rhosts))
        print("Referers to those Hosts include: " + str(self.referers))
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


# cap = rdpcap("/root/Desktop/pcaps/TAKE_THIS.pcap")
cap = PcapReader("/root/Desktop/pcaps/TAKE_THIS.pcap")
# cap = PcapReader("/root/Desktop/Small.pcap")
print("Read Capture")

AccessPointDict = {}
ClientDict = {}
DeviceDict = {}


# noinspection PyShadowingNames
def process_beacon(num, packet):
    print("Processing beacon " + str(num))
    mac = packet[Dot11].addr2
    if mac in AccessPointDict:
        AccessPointDict[mac].frame_numbers.append(num)
    else:
        AccessPointDict[mac] = AccessPoint(mac)
        ap = AccessPointDict[mac]
        ap.set_attribute('frame_numbers', num)

        # set ssid
        ssid = packet[Dot11Beacon].payload.info.decode('utf-8')
        ap.set_attribute('ssid', ssid)

        # set channel
        channel = int.from_bytes(packet[4].info, byteorder='big')
        ap.channel = channel

        # find all rates and set rates

        #  #Supported Rates
        rates_bytes = bytearray(packet[3].info)
        rates = []
        for i in rates_bytes:
            if i > 60:
                i -= 128
            rates.append(i / 2)

        # #Extended Supported Rates
        esrates_bytes = bytearray(packet[7].info)
        for i in esrates_bytes:
            rates.append(i / 2)
        ap.rates = rates

        # set the cypher and encrpytion
        arr = bytearray(packet[8].info)
        try:
            if arr[5] == 4:
                ap.cypher = "AES"
                ap.enc = "WPA2"
            elif arr[5] == 2:
                ap.cypher = "TKIP"
                ap.enc = "WPA"
            else:
                ap.cypher = "RCv4"
                ap.enc = "OPEN or WEP"
        except IndexError:
            ap.cypher = "RCv4"
            ap.enc = "OPEN or WEP"

        # set mode
        try:
            if packet[15].ID == 192:
                ap.mode = 'AC'
        except IndexError:
            pass
        try:
            if packet[10].ID == 45:
                ap.mode = 'N'
        except IndexError:
            pass
        if ap.mode is None:
            if ap.channel > 14:
                ap.mode = 'A'
            elif 54.0 in ap.rates:
                ap.mode = 'G'
            else:
                ap.mode = 'B'


# noinspection PyShadowingNames
def process_arp(num, packet):
    print("Processing arp packet " + str(num))
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


# noinspection PyShadowingNames
def process_http(num, packet):
    print("Processing http packet " + str(num))
    mac = packet[Dot11].addr2
    bssid = packet[Dot11].addr1
    net = AccessPointDict[bssid].ssid
    if len(net) == 1:
        net = net[0]
    if mac not in ClientDict.keys():
        ClientDict[mac] = Client(mac)
    dev = ClientDict[mac]
    dev.set_attribute('networks', net)
    dev.set_attribute('ip', packet[IP].src)
    dev.set_attribute('destination_ip', packet[IP].dst)

    # Http information
    try:
        load = packet[6].load
        load_list = load.decode('utf-8').split('\n')
        if 'GET' in load_list[0]:
            uri = load_list[0][4:]
            dev.set_attribute('frame_numbers', num)
            for i in load_list:
                if 'User-Agent' in i:
                    ua = i[12:]
                    dev.set_attribute('user_agent_string', ua)
                    info = simple_detect(ua)
                    dev.set_attribute('os', info[0])
                    dev.set_attribute('browser', info[1])
                elif 'Host' in i:
                    fulluri = str(i[6:-1]) + uri
                    if 'HTTP/1.1' in fulluri[-10:]:
                        dev.set_attribute('uris', fulluri[:-10])
                    else:
                        dev.set_attribute('uris', fulluri)
                    dev.set_attribute('rhosts', str(i[6:-1]))
                elif 'Referer' in i:
                    dev.set_attribute('referers', str(i[9:-1]))
    except IndexError:
        pass
    except UnicodeDecodeError:
        pass



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


def get_oui(mac):
    with open('betterOUI', 'r') as OUI:
        mac = str(mac).upper()
        mac = mac.replace(':', '')
        mac = mac[:6]
        for line in OUI:
            line = line.split('~')
            if line[0] == mac:
                return line[1].strip()


packet_num = 0
for packet in cap:
    packet_num += 1
    if Dot11Beacon in packet:
        process_beacon(packet_num, packet)
    elif ARP in packet:
        process_arp(packet_num, packet)
    elif TCP in packet:
        if packet[TCP].dport == 80:
            process_http(packet_num, packet)

for k, v in AccessPointDict.items():
    v.show()
# noinspection PyRedeclaration
for k, v in ClientDict.items():
    v.show()
for k, v in DeviceDict.items():
    if (k not in AccessPointDict) and (k not in ClientDict):
        v.show()
