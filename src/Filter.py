import sys
import re
from PyQt4 import QtGui
from PyQt4 import QtCore

class FilterGUI(QtGui.QDialog):
    def __init__(self, rule='' , parent=None):
 
        QtGui.QDialog.__init__(self, parent=parent)
        self.setWindowTitle('Set_Filter')

        self.rule=rule
        self.ModifiedValues={'Protocol':'','Source':'','Destination':'','Src Port':'','Dst Port':''}
        
        self.vbox = QtGui.QVBoxLayout()
        cnt=0
        for key in ['Protocol','Source','Destination','Src Port','Dst Port']:
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
        
        self.btn_OK.clicked.connect(self.accept )
        self.btn_Cancel.clicked.connect(self.reject) 
        
        hbox = QtGui.QHBoxLayout()   
        hbox.addWidget(self.btn_OK)
        hbox.addWidget(self.btn_Cancel)
        self.vbox.addLayout(hbox)
        self.setLayout(self.vbox)
        
        self.rule=self.QInputBox()
        
        self.show()
        
    def GetOriginValue(self):
        '''
        #~ if the user click btn_Cancel,then return OriginValues
        '''
        return self.OriginValues
    
    def GetModifiedValues(self):
        '''
        #~ if the user click btn_OK,then return self.ModifiedValues
        '''
        cnt=0
        for key in ['Protocol','Source','Destination','Src Port','Dst Port']:
            keyStr=str(key)
            VLEObjectName='VLE'+str(cnt)
            VLE=self.findChild((QtGui.QLineEdit, ),VLEObjectName)
            cnt=cnt+1
            self.ModifiedValues[key]=str(VLE.text()) 
        return self.ModifiedValues

    def QInputBox(self):
        RValues=''
        if ( self.exec_() == QtGui.QDialog.Accepted):
           tmp = self.GetModifiedValues()
        else:
           return self.rule
        for key in ['Protocol','Source','Destination','Src Port','Dst Port']:
           if (key == 'Protocol'):
               if (checkproto(tmp[key])):
                   tmp[key] = tmp[key].lower()
               else:
                   tmp[key] = ''
           elif((key == 'Source') & (tmp[key]!='')):
               if (checkip(tmp[key])):
                   tmp[key] = 'src host ' +tmp[key]
               else:
                   tmp[key] = ''
           elif((key == 'Destination')& (tmp[key]!='')):
               if (checkip(tmp[key])):
                   tmp[key] = 'dst host ' +tmp[key]
               else:
                   tmp[key] = ''
           elif((key == 'Src Port')& (tmp[key]!='')):
                   tmp[key] = 'src port ' +tmp[key]
           elif((key == 'Dst Port')& (tmp[key]!='')):
                   tmp[key] = 'dst port ' +tmp[key]
        for key in tmp:
            if (RValues==''):
                RValues=RValues+tmp[key]
            elif(tmp[key]!=''):
                RValues=RValues + ' and ' + tmp[key]
        return RValues

def checkip(ip):  
    p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')  
    if p.match(ip):  
        return True  
    else:  
        return False
def checkproto(proto):
    p = re.compile('(T|t)(C|c)(P|p)|(U|u)(D|d)(P|p)|(A|a)(R|r)(P|p)|(I|i)(C|c)(M|m)(P|p)')
    if p.match(proto):  
        return True  
    else:  
        return False
#~ #-------------------------------------------------
#def main():
#   app = QtGui.QApplication(sys.argv)  # A new instance of QApplication
#   test = FilterGUI('vvv')
#   print test.rule
#if __name__ == '__main__': 
#   main()

