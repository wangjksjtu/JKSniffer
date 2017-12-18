from scapy.all import *

def hexdump(x):
   x=str(x)
   l = len(x)
   i = 0
   while i < l:
       print "%04x  " % i,
       for j in range(16):
           if i+j < l:
               print "%02X" % ord(x[i+j]),
           else:
               print "  ",
           if j%16 == 7:
               print "",
       print " ",
       print sane_color(x[i:i+16])
       i += 16

def hexdumpString(x):
    x = str(x)
    l = len(x)
    i = 0
    out = ""
    while i < l:
        out += "%04x  " % i
        out += " "
        for j in range(16):
            if i + j < l:
                out += "%02X" % ord(x[i + j])
                out += " "
            else:
                out += "  " + " "
            if j % 16 == 7:
                out += "" + " "
        out += " " + " "
        out += sane_color(x[i:i + 16])
        out += "\n"
        i += 16
    return out