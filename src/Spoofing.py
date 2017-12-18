import sys
import re
from PyQt4 import QtGui
from PyQt4 import QtCore
from arp_spoofing import *

#TARGET_IP       =   '10.162.108.135'
#GATEWAY_IP      =   '10.162.0.1'
#PACKET_COUNT    =   1000

class SpoofingGUI(QtGui.QDialog):
    def __init__(self, interface, rule='', parent=None):
        self.interface = interface
        QtGui.QDialog.__init__(self, parent=parent)
        self.setWindowTitle('Arp Spoofing')

        self.rule=rule
        self.ModifiedValues={'Target IP    ':"",'Gateway IP':"",'Packet Cnt ':""}
        
        self.vbox = QtGui.QVBoxLayout()
        cnt=0
        for key in ['Target IP    ','Gateway IP','Packet Cnt ']:
            keyStr=str(key)
            label=keyStr+' :'
            KeyLabel=QtGui.QLabel(label)
            ValueLineEdit=QtGui.QLineEdit(str(self.ModifiedValues[key]))
            ValueLineEdit.setObjectName('VLE'+str(cnt))            
            hbox = QtGui.QHBoxLayout()
            hbox.addWidget(KeyLabel)
            hbox.addWidget(ValueLineEdit)            
            self.vbox.addLayout(hbox)
            cnt=cnt+1
        
        self.btn_OK=QtGui.QDialogButtonBox(QtGui.QDialogButtonBox.Ok)
        self.btn_Cancel=QtGui.QDialogButtonBox(QtGui.QDialogButtonBox.Cancel)
        
        self.btn_OK.clicked.connect(self.accept)
        self.btn_Cancel.clicked.connect(self.reject) 
        
        hbox = QtGui.QHBoxLayout()   
        hbox.addWidget(self.btn_OK)
        hbox.addWidget(self.btn_Cancel)
        self.vbox.addLayout(hbox)
        self.setLayout(self.vbox)

        self.show()
    
    def GetModifiedValues(self):
        '''
        #~ if the user click btn_OK,then return self.ModifiedValues
        '''


    def accept(self):
        cnt=0
        for key in ['Target IP    ','Gateway IP','Packet Cnt ']:
            keyStr=str(key)
            VLEObjectName='VLE'+str(cnt)
            VLE=self.findChild((QtGui.QLineEdit, ),VLEObjectName)
            cnt=cnt+1
            self.ModifiedValues[key]=str(VLE.text())

        try:
            print self.interface
            print self.ModifiedValues["Gateway IP"], self.ModifiedValues['Target IP    '], \
                  self.ModifiedValues['Packet Cnt ']
            self.arp_spoofing = ARP_Spoofing(self.interface, self.ModifiedValues["Gateway IP"], \
                                             self.ModifiedValues['Target IP    '], \
                                             self.ModifiedValues['Packet Cnt '])
            self.arp_spoofing.spoof()
            print "here"
        except:
            QtGui.QMessageBox.critical(self, "ARP Spoofing", "Can not get Mac Address. \nInvalid Format! (Please check manual first)")

        return self.ModifiedValues




