from scapy.all import *

packet = IP(src="10.0.99.100",dst="10.1.99.100")/ICMP()/"Hello World"
print packet.show()
print hexdump(packet)

print str(packet).encode("HEX")
print str(packet)

wrpcap("test.pcap", packet)

packet2 = rdpcap("test.pcap")
print packet2.show()
print packet2.summary()
print hexdump(packet)

#for b in str(packet2):
#    print "char: %s ord/value: %d hex: %x"%(b,ord(b),ord(b))

