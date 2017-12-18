from scapy.all import *

class Packet():
    def __init__(self, id = None, time = None, src = None, dst = None, proto = None, info = None, packet = None):
        self.id = id
        self.time = time
        self.src = src
        self.dst = dst
        self.proto = proto
        self.info = info
        self.packet = packet

    def get_tuple(self):
        return self.id, self.time, self.src, self.dst, self.proto, self.info

    def get_list(self):
        return list(self.get_tuple())

    def parser(self):
        if self.proto == 'IPv6':
            self.IP = self.getInfo_IPv6()
        else:
            self.IP = self.getInfo_IP()

        self.Ethernet = self.getInfo_Ethernet()

        self.getInfo_Protocol()


    def getInfo_IP(self):
        contents = ['version', 'ihl', 'tos', 'len','id', 'flags', 'frag', \
                    'ttl', 'proto', 'chksum', 'src', 'dst', 'options']
        answers = []
        for content in contents:
            try:
                answers.append(getattr(self.packet.getlayer(IP), content))
            except:
                return [""], [""]
        return contents, answers

    def getInfo_IPv6(self):
        contents = ['version', 'tc', 'fl', 'plen', 'nh', \
                    'hlim', 'src', 'dst']
        answers = []
        for content in contents:
            try:
                answers.append(getattr(self.packet.getlayer(IPv6), content))
            except:
                return [""], [""]
        return contents, answers

    def getInfo_TCP(self):
        contents = ['Protocol', 'sport', 'dport', 'seq', 'ack', 'dataofs', 'reserved', 'flags', \
                    'window', 'chksum', 'urgptr', 'options']
        answers = ['TCP']
        for content in contents[1:]:
            try:
                answers.append(getattr(self.packet.getlayer(TCP), content))
            except:
                return [""], [""]
        self.Protocol = (contents, answers)
        print contents, answers

    def getInfo_ICMP(self):
        contents = ['Protocol', 'type', 'code', 'chksum', 'id', 'seq']
        answers = ['ICMP']
        for content in contents[1:]:
            try:
                answers.append(getattr(self.packet.getlayer(ICMP), content))
            except:
                return [""], [""]
        self.Protocol = (contents, answers)
        print contents, answers

    def getInfo_UDP(self):
        contents = ['Protocol', 'sport', 'dport', 'len', 'chksum']
        answers = ['UDP']
        for content in contents[1:]:
            try:
                answers.append(getattr(self.packet.getlayer(UDP), content))
            except:
                return [""], [""]
        self.Protocol = (contents, answers)
        print contents, answers

    def getInfo_ARP(self):
        contents = ['Protocol', 'hwtype', 'ptype', 'hwlen', 'plen', 'op', 'hwsrc', 'psrc', 'hwdst', 'pdst']
        answers = ['ARP']
        for content in contents[1:]:
            try:
                answers.append(getattr(self.packet.getlayer(ARP), content))
            except:
                return [""], [""]
        self.Protocol = (contents, answers)
        print contents, answers

    def getInfo_Ethernet(self):
        contents = ['src', 'dst', 'type']
        answers = []
        for content in contents:
            try:
                answers.append(getattr(self.packet.getlayer(Ether), content))
            except:
                return [""], [""]
        self.Protocol = (contents, answers)
        return contents, answers

    def getInfo_IMCPv6ND_RA(self):
        contents = ['Protocol', 'type', 'code', 'cksum', 'chlim', 'M', 'O', \
                    'H', 'prf', 'P', 'res', 'routerlifetime', 'reachabletime', \
                    'retranstimer']
        answers = ['ICMPv6ND_RA']
        for content in contents[1:]:
            try:
                answers.append(getattr(self.packet.getlayer(ICMPv6ND_RA), content))
            except:
                return [""], [""]
        self.Protocol = (contents, answers)
        print contents, answers

    def getInfo_Protocol(self):
        #print self.proto
        if self.proto == 'IPv6':
            layer = self.packet.summary().split("/")[2].strip()
            if layer == 'ICMPv6ND_RA':
                self.getInfo_IMCPv6ND_RA()
            else:
                pass
        elif self.proto == 'TCP':
            self.getInfo_TCP()
        elif self.proto == 'ARP':
            self.getInfo_ARP()
        elif self.proto == 'UDP':
            self.getInfo_UDP()
        else:
            self.Protocol = ([""], [""])
        #print "Final"
        #print self.Protocol
