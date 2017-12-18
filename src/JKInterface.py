from scapy.all import *
import fcntl

class JKInterface():
    def __init__(self):
        self.init_interface()
        self.filter = None
        #self.specify_iface("lo")
        #print self.ip_addr
        #print self.interface
        self.packets = []
        self.src, self.dst, self.info, self.proto = [], [], [], []
        self.isFirstTime = True
        self.count = 0
        #print self.interface

    def init_interface(self):
        self.ifaceDict = self.get_iface_name()
        self.ifaceList = self.ifaceDict.keys()
        self.ipList = self.get_ip_list()
        self.interface = self.ifaceList[0]
        self.ip_addr = self.ipList[0]
        #print "------------------------"
        #print self.ifaceDict
        #print self.ifaceList
        #print self.ipList

    def specify_iface(self, iface_name):
        if iface_name in self.ifaceList:
            index = self.ifaceList.index(iface_name)
            self.interface = iface_name
            self.ip_addr = self.ipList[index]
        else:
            print "[Error: %s is not existent]" % iface_name

    def get_ip_list(self):
        ipList = []
        for i in range(len(self.ifaceList)):
            #print self.ifaceList[i]
            #print self.get_ip_address(self.ifaceList[i])
            ipList.append(self.get_ip_address(self.ifaceList[i]))
        return ipList

    def get_ip_address(self, ifname):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            addr = socket.inet_ntoa(fcntl.ioctl(
                s.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack('256s', ifname[:15])
            )[20:24])
            return addr
        except:
            return ""

    def get_iface_name(self):
        with open('/proc/net/dev') as f:
            net_dump = f.readlines()
        device_data = {}
        for line in net_dump[2:]:
            line = line.split(':')
            device_data[line[0].strip()] = format(float(line[1].split()[0]) / (1024.0 * 1024.0),
                                                  '0.2f') + " MB;" + format(
                float(line[1].split()[8]) / (1024.0 * 1024.0), '0.2f') + " MB"
        return device_data

    def get_iface_list(self):
        return self.ifaceList

if __name__ == "__main__":
    interfaceSniffer = JKInterface()
    print interfaceSniffer.interface
    print interfaceSniffer.get_iface_name()
    print interfaceSniffer.get_ip_list()
    print interfaceSniffer.get_iface_list()
