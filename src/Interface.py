from PyQt4 import QtGui, QtCore
from JKInterface import JKInterface

class InterfaceGUI(QtGui.QDialog):
    def __init__(self, parent=None, interface=None):
        QtGui.QDialog.__init__(self, parent)
        self.resize(500, 200)
        self.setWindowTitle(u'Interface Selection')
        #screen = QtGui.QDesktopWidget().screenGeometry()
        #size = self.geometry()
        #self.move((screen.width()-size.width())/2, (screen.height()-size.height())/2)
        self.sniffer = JKInterface()
        if interface is None:
            self.interface = self.sniffer.interface
        else:
            self.interface = interface
        self.initUI()
        self.show()

    def initUI(self):
        device_data = self.sniffer.ifaceDict
        iface_num = len(device_data)
        iface_keys = device_data.keys()
        ipList = self.sniffer.ipList

        self.radio_lists = []
        self.gridlayout = QtGui.QGridLayout()
        self.label_name = QtGui.QLabel('Interface')
        self.label_ip = QtGui.QLabel('Address')
        self.label_receive = QtGui.QLabel('Traffic (Accept)')
        self.label_send = QtGui.QLabel('Traffic (Send)')
        self.gridlayout.addWidget(self.label_name, 1, 1)
        self.gridlayout.addWidget(self.label_ip, 1, 2)
        self.gridlayout.addWidget(self.label_receive, 1, 3)
        self.gridlayout.addWidget(self.label_send, 1, 4)
        self.setLayout(self.gridlayout)
        for i in range(iface_num):
            iface_name = iface_keys[i]
            self.iface_radio = QtGui.QRadioButton(iface_name)
            if iface_name == self.interface:
                self.iface_radio.setChecked(True)
            self.gridlayout.addWidget(self.iface_radio, i+2, 1)
            self.radio_lists.append(self.iface_radio)
            self.ip_label = QtGui.QLabel(ipList[i])
            self.gridlayout.addWidget(self.ip_label, i+2, 2)
            data = device_data[iface_name].split(';')
            self.receive_label = QtGui.QLabel(data[0])
            self.send_label = QtGui.QLabel(data[1])
            self.gridlayout.addWidget(self.receive_label, i+2, 3)
            self.gridlayout.addWidget(self.send_label, i+2, 4)
            self.setLayout(self.gridlayout)

        self.start_but = QtGui.QPushButton(u'Okay', self)
        self.start_but.clicked.connect(self.exit)
        self.start_but.setCheckable(False)
        self.gridlayout.addWidget(self.start_but, iface_num + 2, 2)
        self.cancel_but = QtGui.QPushButton(u'Cancel', self)
        self.connect(self.cancel_but, QtCore.SIGNAL('clicked()'), QtCore.SLOT('close()'))
        self.cancel_but.setCheckable(False)
        self.gridlayout.addWidget(self.cancel_but, iface_num + 2, 3)

    def exit(self):
        for radio in self.radio_lists:
            if radio.isChecked():
                self.interface = str(radio.text())
        self.setVisible(False)
        #return self.interface