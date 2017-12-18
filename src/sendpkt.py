import sys
import re
import struct
from scapy.all import *
from PyQt4 import QtGui
from PyQt4 import QtCore

class SendpktGUI(QtGui.QDialog):
    def __init__(self,parent=None):
 
        QtGui.QDialog.__init__(self, parent=parent)
        self.setWindowTitle('SendPacket')

        self.values={'IPsrc':'', 'IPdst':'','IPttl':'64'
                     ,'TCPsport':'0','TCPdport':'0'
                     ,'UDPsport':'0','UDPdport':'0'
                     ,'Datatype':'','Data':'0,0,0'
                     ,'Inter':'','Count':''}        

        self.vbox = QtGui.QVBoxLayout()
        cnt=0
        for key in ['IPsrc','IPdst','IPttl'
                     ,'TCPsport','TCPdport'
                     ,'UDPsport','UDPdport'
                     ,'Datatype','Data'
                     ,'Inter','Count']:
            keyStr=str(key)
            label=keyStr+' :'
            KeyLabel=QtGui.QLabel(label)
            ValueLineEdit=QtGui.QLineEdit(str(self.values[key]))
            ValueLineEdit.setObjectName('VLE'+str(cnt))            
            hbox = QtGui.QHBoxLayout()
            hbox.addWidget(KeyLabel)
            hbox.addWidget(ValueLineEdit)            
            self.vbox.addLayout(hbox)
            cnt=cnt+1
        
        self.btn_OK=QtGui.QDialogButtonBox(QtGui.QDialogButtonBox.Ok)
        self.btn_Cancel=QtGui.QDialogButtonBox(QtGui.QDialogButtonBox.Cancel)
        
        self.btn_OK.clicked.connect(self.accept )
        self.btn_Cancel.clicked.connect(self.reject) 
        
        hbox = QtGui.QHBoxLayout()   
        hbox.addWidget(self.btn_OK)
        hbox.addWidget(self.btn_Cancel)
        self.vbox.addLayout(hbox)
        self.setLayout(self.vbox)

        
        self.inter=0
        self.count=0
        self.pktrule=self.QInputBox()
        
        self.show()
        
    def GetValues(self):
        '''
        #~ if the user click btn_OK,then return self.ModifiedValues
        '''
        cnt=0
        for key in ['IPsrc','IPdst','IPttl'
                     ,'TCPsport','TCPdport'
                     ,'UDPsport','UDPdport'
                     ,'Datatype','Data'
                     ,'Inter','Count']:
            keyStr=str(key)
            VLEObjectName='VLE'+str(cnt)
            VLE=self.findChild((QtGui.QLineEdit, ),VLEObjectName)
            cnt=cnt+1
            self.values[key]=str(VLE.text()) 
        return self.values

    def QInputBox(self):
        if ( self.exec_() == QtGui.QDialog.Accepted):
           tmp = self.GetValues()
        else:
           return ''

        try:
            self.inter=int(tmp['Inter'])
            self.count=int(tmp['Count'])
            data = struct.pack(tmp['Datatype'], int(tmp['Data'].split(',')[0]), int(tmp['Data'].split(',')[1]), int(tmp['Data'].split(',')[2]))

            if (((tmp['TCPsport']!='')|(tmp['TCPdport']!=''))&(tmp['UDPsport']=='')&(tmp['UDPdport']=='')):
                RValues=IP(src=tmp['IPsrc'],dst=tmp['IPdst'],ttl=int(tmp['IPttl']))/TCP(sport=int(tmp['TCPsport']),dport=int(tmp['TCPdport']))/data
            elif (((tmp['UDPsport']!='')|(tmp['UDPdport']!=''))&(tmp['TCPsport']=='')&(tmp['TCPdport']=='')):
                RValues=IP(src=tmp['IPsrc'],dst=tmp['IPdst'],ttl=int(tmp['IPttl']))/UDP(sport=int(tmp['UDPsport']),dport=int(tmp['UDPdport']))/data
            else :
                RValues=None
        except:
            QtGui.QMessageBox.critical(self, "Warning", 'Valid Format! (Please check the manual first)')
            return ''

        return RValues
