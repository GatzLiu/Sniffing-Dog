# Sniffing-Dog
Sniffing Dog is a free and open source packet analyzer. It is used for network troubleshooting, analysis, software and communications protocol development.

-- Basic Information --
Projectname：Sniffing-Dog
Author：GatzLiu
Date：2016-12-28

-- Operating environment --
Liunx（Ubuntu 12.04/14.04/16.04）
Qt5.0 and following versions

-- Function --
Sniffing Dog has the functions of capturing physical layer data frames, analyzing IP, ARP, TCP, UDP, ICMP, HTTP and FTP protocols. It can display the basic information of protocol packets, including capture number, capture time, source IP / MAC, destination IP / MAC, protocol type, packet size, and full content for a specific protocol packet, including hexadecimal encoding and source information.
![image](https://github.com/GatzLiu/Sniffing-Dog/raw/master/picture/protocol_architecture.JPG)

-- Running method --
1. Open and run the program in QT. 
If the permissions are incorrect(eth0:you dont have permission to capture on that device(socket:Operation net permitted)), 
take the following actions.
2. Switch to the project directory and enter ‘qmake’,'make' and 'sudo ./net8' to run the program
Reference：My blog http://blog.csdn.net/gitzliu/article/details/53996484
![这里写图片描述](http://img.blog.csdn.net/20170603161554557?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQvR2l0ekxpdQ==/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70/gravity/SouthEast)
-- Files introduction --
main.cpp: This file is related to the interface.
mainwindow.h: This file is related to class definition and specific logic implementation.
mainwindow.cpp: This file should have been related to the implementation of the specific logic, but I implemented in the mainwindow.h.

-- System flowchart --
![image](https://github.com/GatzLiu/Sniffing-Dog/raw/master/picture/system_flowchart.JPG)

-- Program display --
![image](https://github.com/GatzLiu/Sniffing-Dog/raw/master/picture/view.JPG)


地址：[GatzLiu's Github [ Snifing-Dog ]](https://github.com/GatzLiu/Sniffing-Dog)
