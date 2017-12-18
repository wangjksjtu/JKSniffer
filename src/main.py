from PyQt4 import QtGui, QtCore
from mainWindow import Ui_MainWindow
from JKInterface import JKInterface
from Interface import InterfaceGUI
from Filter import FilterGUI
from sendpkt import SendpktGUI
import threading
from scapy.all import *
from packet import Packet
import scapy_http.http
from utils.hexdump import hexdumpString
import os
import struct

class JKSnifferGUI(QtGui.QMainWindow, Ui_MainWindow):
    def __init__(self):
        super(self.__class__, self).__init__()
        self.setupUi(self)
        self.bind_action()
        self.init_interface()
        self.init_sniffer()
        self.init_treeView()
        self.init_variables()
        self.init_others()

    def init_variables(self):
        self.valid_filter = True
        self.priviledge = True
        self.reassembling_fragdata={}
        self.reassembling_resultdata={}

    def init_others(self):
        self.packetsList.setSortingEnabled(False)

    def closeEvent(self, QCloseEvent):
        self.my_close()

    def init_treeView(self):
        self.packetsList.itemSelectionChanged.connect(self.select_packet)

    def init_interface(self):
        self.interfaceSniffer = JKInterface()
        self.interface = self.interfaceSniffer.interface

    def init_sniffer(self):
        self.STOP = True
        self.filter = None
        self.packets = []
        self.pkts = []
        self.counter = 0
        self.items = []

      
    def bind_action(self):
        self.actionQuit.triggered.connect(self.my_close)
        self.actionOpen.triggered.connect(self.open)
        self.actionSave_as.triggered.connect(self.save)
        self.actionConvert_PDF.triggered.connect(self.pdf)
        self.actionAbout.triggered.connect(self.about)
        self.actionFilter.triggered.connect(self.do_filter)
        self.actionFRestore.triggered.connect(self.restore_filter)
        self.actionInterface.triggered.connect(self.interface)
        self.actionPacket.triggered.connect(self.pkt_send)
        self.actionStart.triggered.connect(self.start)
        self.actionStop.triggered.connect(self.stop)
        self.actionClear.triggered.connect(self.clean)
        self.filtersApplyBtn.clicked.connect(self.specify_filter)
        self.srchbackBtn.clicked.connect(self.srch_back)
        self.srchApplyBtn.clicked.connect(self.search)
        self.actionStop.setEnabled(False)
        #self.actionPerference.triggered.connect(self.interface)


    def clear(self):
        self.packetsList.clear()

    def select_packet(self):
        self.tab_ethernet_list.clear()
        self.tab_ip_list.clear()
        self.tab_protocol_list.clear()

        selected = self.packetsList.selectedItems()
        if not selected == []:
            selected = selected[0]

        fullPacket = next((packet for packet in self.pkts if packet.id == int(selected.text(1))), None)

        #print fullPacket
        #print type(fullPacket)
        #print len(self.packets)
        #print fullPacket.id
        #print self.packets[fullPacket.id - 1]
        #hexdumpString = hexdump.hexdump(self.packets[fullPacket.id], 'return')
        if not fullPacket is None:
            hexString =  hexdumpString(self.packets[fullPacket.id - 1])
            self.tab_packet_hexdump.setText(hexString)
            #self.tab_reassembling_hexdump.setText(hexString)

            packet = self.pkts[fullPacket.id - 1]

            keys,values = packet.Ethernet
            for i in range(len(keys)):
                item = QtGui.QTreeWidgetItem(self.tab_ethernet_list)
                item.setText(0, str(keys[i]))
                item.setText(1, str(values[i]))

            keys,values = packet.IP
            if values!=['']:#not ARP
              if self.reassembling_resultdata.has_key(values[4]):
                  self.tab_reassembling_hexdump.setText(hexdumpString(self.reassembling_resultdata[values[4]]))
              else:
                 self.tab_reassembling_hexdump.setText(hexString)
            else:
                 self.tab_reassembling_hexdump.setText(hexString)
            for i in range(len(keys)):
                item = QtGui.QTreeWidgetItem(self.tab_ip_list)
                item.setText(0, str(keys[i]))
                item.setText(1, str(values[i]))

            #self.packetDetail.setTabText(3, fullPacket.layers[2]['LayerType'])

            keys, values = packet.Protocol
            for i in range(len(keys)):
                item = QtGui.QTreeWidgetItem(self.tab_protocol_list)
                item.setText(0, str(keys[i]))
                item.setText(1, str(values[i]))


    def add_packet(self, pkt):
        #print pkt
        #print pkt.id
        item = QtGui.QTreeWidgetItem(self.packetsList)
        item.setText(0, "%.6f" % round(pkt.time, 6))
        item.setText(1, str(pkt.id))
        item.setText(2, pkt.src)
        item.setText(3, pkt.dst)
        item.setText(4, pkt.info)
        item.setText(5, pkt.proto)
        self.items.append(item)
    
    def pkt_callback(self, packet):
        #pkt.show()
        if self.counter == 0:
            self.init_time = packet.time
        self.counter += 1
        pkt = Packet(id = self.counter)
        if int(packet.getlayer(Ether).type) == 34525:
            pkt.proto = 'IPv6'
            pkt.time = packet.time - self.init_time
            pkt.src = str(packet.getlayer(IPv6).src)
            pkt.dst = str(packet.getlayer(IPv6).dst)
            pkt.info = str(packet.summary())
            #self.packet_table.row_append(src, dst, proto, info)
            self.packets.append(packet)
            self.pkts.append(pkt)
        elif int(packet.getlayer(Ether).type) == 2048:
            if int(packet.getlayer(IP).proto) == 6:
                pkt.proto = 'TCP'
            elif int(packet.getlayer(IP).proto) == 17:
                pkt.proto = 'UDP'
            elif int(packet.getlayer(IP).proto) == 1:
                pkt.proto = 'ICMP'
            pkt.time = packet.time - self.init_time
            pkt.src = str(packet.getlayer(IP).src)
            pkt.dst = str(packet.getlayer(IP).dst)
            pkt.info = str(packet.summary())
            #self.packet_table.row_append(src, dst, proto, info)
            
 
            self.packets.append(packet)
            self.pkts.append(pkt)
        elif int(packet.getlayer(Ether).type) == 2054:
            pkt.proto = 'ARP'
            pkt.time = packet.time - self.init_time
            pkt.src = str(packet.getlayer(ARP).psrc)
            pkt.dst = str(packet.getlayer(ARP).pdst)
            pkt.info = str(packet.summary())
            #self.packet_table.row_append(src, dst, proto, info)
            self.packets.append(packet)
            self.pkts.append(pkt)
        else:
            print "here"
            self.counter -= 1
            return

        pkt.packet = packet
        pkt.parser()
        if pkt.proto=='ICMP' or pkt.proto=='UDP' or pkt.proto=='TCP':  #values[5]=flags values[6]=frag
            keys,values = pkt.getInfo_IP()
            if values[5]==0x01 or (values[5]==0x00 and values[6]>0):
                self.reassembling_fragdata.setdefault(values[4],{})               
                self.reassembling_fragdata[values[4]][values[6]]=pkt.packet
                for frag_tmp in sorted(self.reassembling_fragdata[values[4]].keys()):
                     if (frag_tmp==sorted(self.reassembling_fragdata[values[4]].keys())[0]):
                        self.reassembling_resultdata[values[4]]=str(self.reassembling_fragdata[values[4]][frag_tmp])
                        self.reassembling_resultdata[values[4]]=self.reassembling_resultdata[values[4]][0:20]+'\x00\x00'+self.reassembling_resultdata[values[4]][22:]
                     else:
                        self.reassembling_resultdata[values[4]]=self.reassembling_resultdata[values[4]]+str(self.reassembling_fragdata[values[4]][frag_tmp])[34:]
                        tos_tmp11,=struct.unpack('B',self.reassembling_resultdata[values[4]][16])
                        tos_tmp12,=struct.unpack('B',self.reassembling_resultdata[values[4]][17])
                        tos_tmp21,=struct.unpack('B',str(self.reassembling_fragdata[values[4]][frag_tmp])[16])
                        tos_tmp22,=struct.unpack('B',str(self.reassembling_fragdata[values[4]][frag_tmp])[17])
                        tos_add=tos_tmp11*256+tos_tmp12+tos_tmp21*256+tos_tmp22-20
                        Barray=bytearray(self.reassembling_resultdata[values[4]])
                        Barray[16]=tos_add/256
                        Barray[17]=tos_add%256
                        self.reassembling_resultdata[values[4]]=str(Barray)
                        
        if not pkt.proto is None:
            self.add_packet(pkt)
        print packet.summary()

    def start(self):
        self.valid_filter = True
        self.STOP = False
        print "-------start-------"
        #self.sniffer()

        self.sniff_thread = threading.Thread(target=self.sniffer)
        self.sniff_thread.start()
        #self.isFirstTime = False

        time.sleep(0.2)
        if self.valid_filter and self.priviledge:
            self.actionStart.setEnabled(False)
            self.actionStop.setEnabled(True)
        elif not self.priviledge:
            QtGui.QMessageBox.warning(self, "Warning", "Permission Denied. (Need Root Priviledge)")
        else:
            QtGui.QMessageBox.critical(self, "Warning", 'Invalid Filter Rule (Use BPF syntax)')
            self.set_filter(None)

    def sniffer(self):
        #sniff(iface=self.interface)
        try:
            sniff(iface=self.interface, prn=self.pkt_callback, \
              filter=self.filter, stop_filter=self.stop_filter)
        except Scapy_Exception:
            self.valid_filter = False
        except:
            self.priviledge = False
            print "Permission Denied"


    def set_filter(self, rule):
        self.filter = rule
        if self.filter == "":
            QtGui.QMessageBox.information(self, "Filter", "You have canceled filter.")
        else:
            QtGui.QMessageBox.information(self, "Filter", "You have changed filter rule to %s." % rule)

    def specify_filter(self):
        if self.actionStop.isEnabled():
            QtGui.QMessageBox.critical(self, "Filter", "Please stop scanning first!")
        else:
            print str(self.filtersInput.text()).strip()
            self.set_filter(str(self.filtersInput.text()).strip())

    def stop_filter(self, x):
        return self.STOP

    def do_filter(self):
        if self.actionStop.isEnabled():
            QtGui.QMessageBox.critical(self, "Filter", "Please stop scanning first!")
        else:
            flt = FilterGUI(parent=self, rule=self.filter)
            #flt.exec_()
            self.set_filter(flt.rule)

    def restore_filter(self):
        if self.actionStop.isEnabled():
            QtGui.QMessageBox.critical(self, "Filter", "Please stop scanning first!")
        else:
            self.set_filter(None)


    def srch_back(self):
        self.packetsList.clear()
        for pkt in self.pkts:
          self.add_packet(pkt)
        self.start()

    def search(self):
        self.packetsList.clear()
        rulestr = str(self.srchInput.text()).strip()
        rule=rulestr.split('=')
        if rule[0]=='src':
           for pkt in self.pkts:
               if pkt.src==rule[1]:
                 self.add_packet(pkt)
        elif rule[0]=='dst':
           for pkt in self.pkts:
               if pkt.dst==rule[1]:
                 self.add_packet(pkt) 
        elif rule[0]=='proto':
           for pkt in self.pkts:
               if pkt.proto==rule[1]:
                 self.add_packet(pkt)        
        self.stop() 


    def pkt_send(self):
        Sendpkt = SendpktGUI(parent=self)
        send(Sendpkt.pktrule,inter=Sendpkt.inter,count=Sendpkt.count)

    def stop(self):
        print "Attempt to stop"
        #self.sniffer.stop()
        self.STOP = True
        self.actionStart.setEnabled(True)
        self.actionStop.setEnabled(False)

    def clean(self):
        self.counter = 0
        #self.filter = None
        self.packets = []
        self.pkts = []
        self.tab_ip_list.clear()
        self.tab_ethernet_list.clear()
        self.packetsList.clear()
        self.tab_protocol_list.clear()
        self.reassembling_resultdata={}  
        self.reassembling_fragdata={}    
   
    def refresh(self, packets):
        self.clean()
        #self.packets = packets
        print len(packets)
        for packet in packets:
            self.pkt_callback(packet)

    def open(self):
        fileName = QtGui.QFileDialog.getOpenFileName(self, "Open File", "../", "Pcap files (*.pcap)")
        if fileName:
            ans = QtGui.QMessageBox.question(self, '', "Are you sure to open new pcap file and clean current packets?", \
                                             QtGui.QMessageBox.Yes | QtGui.QMessageBox.No)
            if ans == QtGui.QMessageBox.Yes:
                try:
                    fileName = str(fileName)
                    pcap = rdpcap(fileName)
                    packets = list(pcap)
                    self.refresh(packets)
                    pass
                except ValueError:
                    QtGui.QMessageBox.information(self, "Error", "'"+fileName+"' is not a pcap file.")
                except:
                    print "Unexpected error:", sys.exc_info()[0]
            else:
                pass

    def save(self):
        if self.counter == 0:
            QtGui.QMessageBox.critical(self, "Error", "Packet list is empty.")
            #QtGui.QMessageBox.information(self, "Error", "Packet list is empty.")
            return
        filename = QtGui.QFileDialog.getSaveFileName(self, "Save file", "../", ".pcap")
        if filename:
            try:
                filename = str(filename)
                pcap_writer = PcapWriter(filename+'.pcap')
                pcap_writer.write(self.packets)
                QtGui.QMessageBox.information(self, "Success", "Save %s successfully!" % filename)
            except:
                print "Unexpected error:", sys.exc_info()[0]

    def interface(self):
        iface = InterfaceGUI(parent=self, interface=self.interface)
        iface.exec_()
        self.interface = iface.interface

    def pdf(self):
        if self.counter == 0:
            QtGui.QMessageBox.critical(self, "Error", "Packet list is empty.")
            #QtGui.QMessageBox.information(self, "Error", "Packet list is empty.")
            return
        selected = self.packetsList.selectedItems()
        if selected == []:
            QtGui.QMessageBox.information(self, "Info", "Please specify a specific packet.")
            return

        selected = selected[0]
        id = int(selected.text(1))
        #try:
        filename = str(QtGui.QFileDialog.getSaveFileName(self, "Save file", "../", ".pdf"))
        packet = self.packets[id - 1]
        print type(packet)
        packet.pdfdump(filename)
        QtGui.QMessageBox.information(self, "Success", "Save %s successfully!" % filename)
        #except:
        #print "Unexpected error:", sys.exc_info()[0]

    def my_close(self):
        self.stop()
        os._exit(0)
        self.close()

    def about(self):
        QtGui.QMessageBox.about(self, "About", "JKSniffer is composed by wangjksjtu.\nFor more information, please visit https://github.com/wangjksjtu")

def main():
    app = QtGui.QApplication(sys.argv)  # A new instance of QApplication
    mainWin = JKSnifferGUI()
    mainWin.show()
    app.exec_()

if __name__ == '__main__':
    main()
    '''
    app = QtGui.QApplication(sys.argv)  # A new instance of QApplication
    mainWin = JKSnifferGUI()
    mainWin.set_filter("tcp")
    mainWin.start()
    '''
