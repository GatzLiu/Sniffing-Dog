## **Sniffing-Dog**<br>
Sniffing Dog is a free and open source packet analyzer. It is used for network troubleshooting, analysis, software and communications protocol development.<br>

## **Basic Information** <br>
Projectname：Sniffing-Dog<br>
Author：GatzLiu<br>
Date：2016-12-28<br>

## **Operating environment** <br>
Liunx（Ubuntu 12.04/14.04/16.04）<br>
Qt5.0 and following versions<br>

## **Function **<br>
Sniffing Dog has the functions of capturing physical layer data frames, analyzing IP, ARP, TCP, UDP, ICMP, HTTP and FTP protocols. It can display the basic information of protocol packets, including capture number, capture time, source IP / MAC, destination IP / MAC, protocol type, packet size, and full content for a specific protocol packet, including hexadecimal encoding and source information.<br>
![这里写图片描述](http://img.blog.csdn.net/20170603162533671?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQvR2l0ekxpdQ==/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70/gravity/SouthEast)

## **Running method**<br>
1. Open and run the program in QT. <br>
If the permissions are incorrect(eth0:you dont have permission to capture on that device(socket:Operation net permitted)), 
take the following actions.<br>
2. Switch to the project directory and enter ‘qmake’,'make' and 'sudo ./net8' to run the program<br>
Reference：My blog [[ GitzLiu-CSDN--QT ]](http://blog.csdn.net/gitzliu/article/details/53996484)<br>

## **Files introduction**<br>
main.cpp: This file is related to the interface.<br>
mainwindow.h: This file is related to class definition and specific logic implementation.<br>
mainwindow.cpp: This file should have been related to the implementation of the specific logic, but I implemented in the mainwindow.h.<br>

## **System flowchart**<br>
![这里写图片描述](http://img.blog.csdn.net/20170603162558674?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQvR2l0ekxpdQ==/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70/gravity/SouthEast)<br>

##**Program display**<br>
![这里写图片描述](http://img.blog.csdn.net/20170603163756346?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQvR2l0ekxpdQ==/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70/gravity/SouthEast)<br>1
 ## **THINKS !**
