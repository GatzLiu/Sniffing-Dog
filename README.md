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
![image](https://github.com/GatzLiu/Sniffing-Dog/raw/master/pictures/protocol_architecture.JPG)

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
![image](https://github.com/GatzLiu/Sniffing-Dog/raw/master/pictures/system_flowchart.JPG)

## **Program display**
![image](https://github.com/GatzLiu/Sniffing-Dog/raw/master/pictures/view.JPG)
 ## **THINKS !**
