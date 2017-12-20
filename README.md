# JKSniffer
An implementation of Sniffer Tool using Python

![icon](https://github.com/wangjksjtu/JKSniffer/blob/master/src/icon/icon.png)

This project is established mainly for its __educational purposes__, which will be a good example for __PyQt__, __Socket__, __Scapy__ and __Threading__. In this project, you will learn how to capture a packet, interpret packets of different protocol (__ARP__, __ICMP__, __IPv4__,  __IPv6__, __TCP__, __UDP__) and create user-friendly GUI with multiple threadings using Python.

### Environment ###
- Python 2.7 (https://www.python.org/)
- Scapy 2.3.2 (http://secdev.org/projects/scapy/)
- Numpy (http://www.numpy.org/)
- Gnuplot (http://www.gnuplot.info/)
- PyX 0.14.1 (http://pyx.sourceforge.net/)
- PyQt4 (http://pyqt.sourceforge.net/Docs/PyQt4/)

### Installation ###
    sudo apt-get install python-scapy, python-numpy
    sudo apt-get install gnuplot, pyxplot
    sudo apt-get install pyqt4
    ...

__Ps__: Install other essential libs if you need to utilize more characteristics of Scapy or reduce warnings in Scapy. Please refer [here](http://scapy.readthedocs.io/en/latest/installation.html) for more detailed information.

### QuickStart ###
It is of great convenience to use this toolkit. Just type following commands in terminal. __Our implementation only supports for Linux now.__ We don't guarantee whether it will work completely in Windows. If you are interested in testing it in Windows. Please let me know.

#### Clone this repository and Run ####

    git clone https://github.com/wangjksjtu/JKSniffer
    cd JKSniffer/src/
    sudo python main.py

#### ScreenShots ####

![MainWindow](https://github.com/wangjksjtu/JKSniffer/blob/master/imgs/JKSniffer.png)
![Capturing](https://github.com/wangjksjtu/JKSniffer/blob/master/imgs/JKSniffer2.png)
![TCP Protocol](https://github.com/wangjksjtu/JKSniffer/blob/master/imgs/TCP.png)

For more details about this tool, please check [docs](https://github.com/wangjksjtu/JKSniffer/docs) of this repository (Chinese).
Any of your contributions to documentations or codes is greatly appreciated.

### Contributor ###
- [_wangjksjtu_](https://github.com/wangjksjtu)
- [_while9608_](https://github.com/while9608)

### Contact Me ###
- wangjksjtu_01@sjtu.edu.cn
- 249446879@qq.com
