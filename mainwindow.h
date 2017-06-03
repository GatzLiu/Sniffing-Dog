#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include<qthread.h>
#include <QMainWindow>
#include <QApplication>
#include <QWidget>
#include <QLabel>
#include <QListWidget>
#include <QHBoxLayout>
#include <QTreeWidget>
#include <QIcon>
#include <QPushButton>
#include <QTextEdit>

#include<QDirModel>
#include <QAbstractItemModel>
#include <QStandardItemModel>
#include <QStringListModel>


#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <pcap.h>
#include <sys/time.h>



#include<malloc.h>


namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private:
    Ui::MainWindow *ui;

};

struct Node {
    int num;         //no
    char td[100];    //time
    char d[100];      //des
    char s[100];      //src
    char tl[100];     //totol long
    char type[100];    //type

    unsigned char payloadsrc[100000];
    unsigned char payloadhex[100000];

    Node *next;
};

class list {
    Node *head;
public:
    list() {
        head = (Node*)malloc(sizeof(Node));
        head->next = NULL;
    }

    void insertlist(Node *ins)//链表结点的插入
    {
        Node *s;
        for (s = head; s->next != NULL; s = s->next);

        s->next = ins;
    }

    Node* find(int num) {
        Node *s = head;
        for (s = head->next; s != NULL; s = s->next)
            if (num == s->num)
                break;

        return s;
    }
};


class Mythread:public QThread
{
    Q_OBJECT
public:
    int number=0;
    long time_long=0;
    double time_double=0;
    struct timeval tv;

    struct pcap_pkthdr hdr;// length
    unsigned char *packet;//content

    QTreeWidget *tree = new QTreeWidget;//global tree
    QTreeWidgetItem *lroot;

    //QTreeWidgetItem * pCurrentItem = this->itemAt(event->pos() );
 //returnroot->treeWidget()->currentItem();


    char num[100]={0};  //把标号转换成 char
    char ti_do[100]={0}; //把时间传转换char
    char to_le[100]={0}; //把长度转换成char

    list li;
    Node *fi;//fi=li.find()
    Node *inse;//insert  malloc


    ////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////
    void fun(char *in, char *out, int len) {

        char ch;
        int i,j;
        i = 0;
        for (j=0; j < len; j++) {
            ch = in[j];
            switch (ch) {
            case '!':
                out[i] = '2'; i++;
                out[i] = '1'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'#':
                out[i] = '2'; i++;
                out[i] = '3'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'$':
                out[i] = '2'; i++;
                out[i] = '4'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'%':
                out[i] = '2'; i++;
                out[i] = '5'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'&':
                out[i] = '2'; i++;
                out[i] = '6'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'(':
                out[i] = '2'; i++;
                out[i] = '8'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case')':
                out[i] = '2'; i++;
                out[i] = '9'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'*':
                out[i] = '2'; i++;
                out[i] = 'A'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'+':
                out[i] = '2'; i++;
                out[i] = 'B'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case',':
                out[i] = '2'; i++;
                out[i] = 'C'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'-':
                out[i] = '2'; i++;
                out[i] = 'D'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'.':
                out[i] = '2'; i++;
                out[i] = 'E'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'/':
                out[i] = '2'; i++;
                out[i] = 'F'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'0':
                out[i] = '3'; i++;
                out[i] = '0'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'1':
                out[i] = '3'; i++;
                out[i] = '1'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'2':
                out[i] = '3'; i++;
                out[i] = '2'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'3':
                out[i] = '3'; i++;
                out[i] = '3'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'4':
                out[i] = '3'; i++;
                out[i] = '4'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'5':
                out[i] = '3'; i++;
                out[i] = '5'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'6':
                out[i] = '3'; i++;
                out[i] = '6'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'7':
                out[i] = '3'; i++;
                out[i] = '7'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'8':
                out[i] = '3'; i++;
                out[i] = '8'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'9':
                out[i] = '3'; i++;
                out[i] = '9'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case':':
                out[i] = '3'; i++;
                out[i] = 'A'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case';':
                out[i] = '3'; i++;
                out[i] = 'B'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'<':
                out[i] = '3'; i++;
                out[i] = 'C'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'=':
                out[i] = '3'; i++;
                out[i] = 'D'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'>':
                out[i] = '3'; i++;
                out[i] = 'E'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'?':
                out[i] = '3'; i++;
                out[i] = 'F'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'@':
                out[i] = '4'; i++;
                out[i] = '0'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'A':
                out[i] = '4'; i++;
                out[i] = '1'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'B':
                out[i] = '4'; i++;
                out[i] = '2'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'C':
                out[i] = '4'; i++;
                out[i] = '3'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'D':
                out[i] = '4'; i++;
                out[i] = '4'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'E':
                out[i] = '4'; i++;
                out[i] = '5'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'F':
                out[i] = '4'; i++;
                out[i] = '6'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'G':
                out[i] = '4'; i++;
                out[i] = '7'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'H':
                out[i] = '4'; i++;
                out[i] = '8'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'I':
                out[i] = '4'; i++;
                out[i] = '9'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'J':
                out[i] = '4'; i++;
                out[i] = 'A'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'K':
                out[i] = '4'; i++;
                out[i] = 'B'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'L':
                out[i] = '4'; i++;
                out[i] = 'C'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'M':
                out[i] = '4'; i++;
                out[i] = 'D'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'N':
                out[i] = '4'; i++;
                out[i] = 'E'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'O':
                out[i] = '4'; i++;
                out[i] = 'F'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'P':
                out[i] = '5'; i++;
                out[i] = '0'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'Q':
                out[i] = '5'; i++;
                out[i] = '1'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'R':
                out[i] = '5'; i++;
                out[i] = '2'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'S':
                out[i] = '5'; i++;
                out[i] = '3'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'T':
                out[i] = '5'; i++;
                out[i] = '4'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'U':
                out[i] = '5'; i++;
                out[i] = '5'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'V':
                out[i] = '5'; i++;
                out[i] = '6'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'W':
                out[i] = '5'; i++;
                out[i] = '7'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'X':
                out[i] = '5'; i++;
                out[i] = '8'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'Y':
                out[i] = '5'; i++;
                out[i] = '9'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'Z':
                out[i] = '5'; i++;
                out[i] = 'A'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'[':
                out[i] = '5'; i++;
                out[i] = 'B'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'\\':
                out[i] = '5'; i++;
                out[i] = 'C'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case']':
                out[i] = '5'; i++;
                out[i] = 'D'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'^':
                out[i] = '5'; i++;
                out[i] = 'E'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'_':
                out[i] = '5'; i++;
                out[i] = 'F'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'`':
                out[i] = '6'; i++;
                out[i] = '0'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'a':
                out[i] = '6'; i++;
                out[i] = '1'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'b':
                out[i] = '6'; i++;
                out[i] = '2'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'c':
                out[i] = '6'; i++;
                out[i] = '3'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'd':
                out[i] = '6'; i++;
                out[i] = '4'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'e':
                out[i] = '6'; i++;
                out[i] = '5'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'f':
                out[i] = '6'; i++;
                out[i] = '6'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'g':
                out[i] = '6'; i++;
                out[i] = '7'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'h':
                out[i] = '6'; i++;
                out[i] = '8'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'i':
                out[i] = '6'; i++;
                out[i] = '9'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'j':
                out[i] = '6'; i++;
                out[i] = 'A'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'k':
                out[i] = '6'; i++;
                out[i] = 'B'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'l':
                out[i] = '6'; i++;
                out[i] = 'C'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'm':
                out[i] = '6'; i++;
                out[i] = 'D'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'n':
                out[i] = '6'; i++;
                out[i] = 'E'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'o':
                out[i] = '6'; i++;
                out[i] = 'F'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'p':
                out[i] = '7'; i++;
                out[i] = '0'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'q':
                out[i] = '7'; i++;
                out[i] = '1'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'r':
                out[i] = '7'; i++;
                out[i] = '2'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case's':
                out[i] = '7'; i++;
                out[i] = '3'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case't':
                out[i] = '7'; i++;
                out[i] = '4'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'u':
                out[i] = '7'; i++;
                out[i] = '5'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'v':
                out[i] = '7'; i++;
                out[i] = '6'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'w':
                out[i] = '7'; i++;
                out[i] = '7'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'x':
                out[i] = '7'; i++;
                out[i] = '8'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'y':
                out[i] = '7'; i++;
                out[i] = '9'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'z':
                out[i] = '7'; i++;
                out[i] = 'A'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'{':
                out[i] = '7'; i++;
                out[i] = 'B'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'|':
                out[i] = '7'; i++;
                out[i] = 'C'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'}':
                out[i] = '7'; i++;
                out[i] = 'D'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            case'~':
                out[i] = '7'; i++;
                out[i] = 'E'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            default:
                out[i] = '0'; i++;
                out[i] = '0'; i++;
                out[i] = ' '; i++;
                out[i] = '\0';
                break;
            }
        }
    }
    ////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////

    void http_packet_callback(unsigned char *argument, const struct pcap_pkthdr *pcap_header,
                                const unsigned char *packet_content)
    {

        printf("\n----ethernet protocol-----\n");//(physical layer)

        printf("Protocol:\t\t\tHTTP\n");

        ///////////////////////////////////////////////////////////////////
               struct iphdr *ipptr;
               ipptr = (struct iphdr *)(packet_content + 14);
               struct in_addr s, d;

                   gettimeofday(&tv,NULL);
                   time_double=(tv.tv_sec*1000000 + tv.tv_usec - time_long)*1.000000/1000000 ;
                   printf("microsecond:\t\t\t%lf\n",time_double);  //微秒

               s.s_addr=ipptr->saddr;
               d.s_addr=ipptr->daddr;
               printf("source address: \t\t%s\n", inet_ntoa(s));
               printf("destination address: \t\t%s\n", inet_ntoa(d));
               printf("total length: \t\t\t%d    \n", ntohs(ipptr->tot_len));


               number++;
               printf("NO.:\t\t\t\t%d\n",number);
               sprintf(num,"%d",number);
               sprintf(ti_do,"%lf",time_double);
               sprintf(to_le,"%d",ntohs(ipptr->tot_len));

               QStringList l;
               l<< QObject::tr(num)<<QObject::tr(ti_do) << QObject::tr(inet_ntoa(s)) << QObject::tr(inet_ntoa(d)) << QObject::tr("HTTP") << QObject::tr(to_le);
               lroot = new QTreeWidgetItem(tree, l);

        //////////////////////////////////////////////////////////////////////////////////

       unsigned int i = 0;

        inse = (Node*)malloc(sizeof(Node));

        printf("Payload src:\t\t\t");
        for (i = 0; i < pcap_header->len; i++) {
            if (isprint(packet_content[i])){
                printf("%c ", packet_content[i]);
                inse->payloadsrc[i]=packet_content[i];
            }
            else{
                printf(". ");
                inse->payloadsrc[i]='.';
            }

            if ((i % 16 == 0 && i != 0) || i == pcap_header->len-1)  //every 16 a row
                printf("\n\t\t\t\t");
        }

        inse->payloadsrc[i]='\0';

        printf("\nPayload hex:\t\t\t");
        for (i = 0; i < pcap_header->len; i++) {
            printf("%x ", packet_content[i]);
            inse->payloadhex[i]=packet_content[i];
            if ((i % 16 == 0 && i != 0) || i == pcap_header->len-1) //every 16 a row
                printf("\n\t\t\t\t");
        }
        inse->payloadhex[i]='\0';
        // 添加到链表/////////////////////////////////////////////////////////////////////////////

        inse->num=number;
        strcpy(inse->td,ti_do);
        strcpy(inse->s,inet_ntoa(s));
        strcpy(inse->d,inet_ntoa(d));
        strcpy(inse->tl,to_le);
        strcpy(inse->type,"HTTP");

       // a.payloadsrc=(unsigned char*)malloc((pcap_header->len+1)*sizeof(unsigned char));
        //strcpy(a.payloadsrc,packet_content);
       // memcpy(inse->payloadsrc,packet_content,pcap_header->len+1);
        inse->next=NULL;

        li.insertlist(inse);

  //////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        return;

    }

    void ftp_packet_callback(unsigned char *argument, const struct pcap_pkthdr *pcap_header,
                                const unsigned char *packet_content)
    {

        printf("\n----ethernet protocol-----\n");//(physical layer

        printf("Protocol:\t\t\tFTP\n");


        ///////////////////////////////////////////////////////////////////
               struct iphdr *ipptr;
               ipptr = (struct iphdr *)(packet_content + 14);
               struct in_addr s, d;

                   gettimeofday(&tv,NULL);
                   time_double=(tv.tv_sec*1000000 + tv.tv_usec - time_long)*1.000000/1000000 ;
                   printf("microsecond:\t\t\t%lf\n",time_double);  //微秒

               s.s_addr=ipptr->saddr;
               d.s_addr=ipptr->daddr;
               printf("source address: \t\t%s\n", inet_ntoa(s));
               printf("destination address: \t\t%s\n", inet_ntoa(d));
               printf("total length: \t\t\t%d    \n", ntohs(ipptr->tot_len));


               number++;
               printf("NO.:\t\t\t\t%d\n",number);
               sprintf(num,"%d",number);
               sprintf(ti_do,"%lf",time_double);
               sprintf(to_le,"%d",ntohs(ipptr->tot_len));

               QStringList l;
               l<< QObject::tr(num)<<QObject::tr(ti_do) << QObject::tr(inet_ntoa(s)) << QObject::tr(inet_ntoa(d)) << QObject::tr("FTP") << QObject::tr(to_le);
               lroot = new QTreeWidgetItem(tree, l);

        //////////////////////////////////////////////////////////////////////////////////

       unsigned int i = 0;
        inse = (Node*)malloc(sizeof(Node));

        printf("Payload src:\t\t\t");
        for (i = 0; i < pcap_header->len; i++) {
            if (isprint(packet_content[i])){
                printf("%c ", packet_content[i]);
                inse->payloadsrc[i]=packet_content[i];
            }
            else{
                printf(". ");
                inse->payloadsrc[i]='.';
            }

            if ((i % 16 == 0 && i != 0) || i == pcap_header->len-1)  //every 16 a row
                printf("\n\t\t\t\t");
        }

        inse->payloadsrc[i]='\0';

        printf("\nPayload hex:\t\t\t");
        for (i = 0; i < pcap_header->len; i++) {
            printf("%x ", packet_content[i]);
            inse->payloadhex[i]=packet_content[i];
            if ((i % 16 == 0 && i != 0) || i == pcap_header->len-1) //every 16 a row
                printf("\n\t\t\t\t");
        }
        inse->payloadhex[i]='\0';
        // 添加到链表/////////////////////////////////////////////////////////////////////////////

        inse->num=number;
        strcpy(inse->td,ti_do);
        strcpy(inse->s,inet_ntoa(s));
        strcpy(inse->d,inet_ntoa(d));
        strcpy(inse->tl,to_le);
        strcpy(inse->type,"FTP");

       // a.payloadsrc=(unsigned char*)malloc((pcap_header->len+1)*sizeof(unsigned char));
        //strcpy(a.payloadsrc,packet_content);
        //memcpy(inse->payloadsrc,packet_content,pcap_header->len+1);
        inse->next=NULL;

        li.insertlist(inse);

  //////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        return;

    }

    void icmp_packet_callback(unsigned char *argument, const struct pcap_pkthdr *pcap_header,
                                const unsigned char *packet_content)
    {
        unsigned int i = 0;

        ///////////////////////////////////////////////////////////////////
               struct iphdr *ipptr;
               ipptr = (struct iphdr *)(packet_content + 14);
               struct in_addr s, d;

                   gettimeofday(&tv,NULL);
                   time_double=(tv.tv_sec*1000000 + tv.tv_usec - time_long)*1.000000/1000000 ;
                   printf("microsecond:\t\t\t%lf\n",time_double);  //微秒

               s.s_addr=ipptr->saddr;
               d.s_addr=ipptr->daddr;
               printf("source address: \t\t%s\n", inet_ntoa(s));
               printf("destination address: \t\t%s\n", inet_ntoa(d));
               printf("total length: \t\t\t%d    \n", ntohs(ipptr->tot_len));


               number++;
               printf("NO.:\t\t\t\t%d\n",number);
               sprintf(num,"%d",number);
               sprintf(ti_do,"%lf",time_double);
               sprintf(to_le,"%d",ntohs(ipptr->tot_len));

               QStringList l;
               l<< QObject::tr(num)<<QObject::tr(ti_do) << QObject::tr(inet_ntoa(s)) << QObject::tr(inet_ntoa(d)) << QObject::tr("ICMP") << QObject::tr(to_le);
               lroot = new QTreeWidgetItem(tree, l);

        //////////////////////////////////////////////////////////////////////////////////
        inse = (Node*)malloc(sizeof(Node));

        printf("Payload src:\t\t\t");
        for (i = 0; i < pcap_header->len; i++) {
            if (isprint(packet_content[i])){
                printf("%c ", packet_content[i]);
                inse->payloadsrc[i]=packet_content[i];
            }
            else{
                printf(". ");
                inse->payloadsrc[i]='.';
            }

            if ((i % 16 == 0 && i != 0) || i == pcap_header->len-1)  //every 16 a row
                printf("\n\t\t\t\t");
        }

        inse->payloadsrc[i]='\0';

        printf("\nPayload hex:\t\t\t");
        for (i = 0; i < pcap_header->len; i++) {
            printf("%x ", packet_content[i]);
            inse->payloadhex[i]=packet_content[i];
            if ((i % 16 == 0 && i != 0) || i == pcap_header->len-1) //every 16 a row
                printf("\n\t\t\t\t");
        }
        inse->payloadhex[i]='\0';
        // 添加到链表/////////////////////////////////////////////////////////////////////////////

         inse->num=number;
         strcpy(inse->td,ti_do);
         strcpy(inse->s,inet_ntoa(s));
         strcpy(inse->d,inet_ntoa(d));
         strcpy(inse->tl,to_le);
         strcpy(inse->type,"ICMP");

        // a.payloadsrc=(unsigned char*)malloc((pcap_header->len+1)*sizeof(unsigned char));
         //strcpy(a.payloadsrc,packet_content);
         //memcpy(inse->payloadsrc,packet_content,pcap_header->len+1);

         inse->next=NULL;

         li.insertlist(inse);

  //////////////////////////////////////////////////////////////////////////////////////////////////////////////////


        return;
    }

    void udp_packet_callback(unsigned char *argument, const struct pcap_pkthdr *pcap_header,
                                const unsigned char *packet_content)
    {
        unsigned int i = 0;
 ///////////////////////////////////////////////////////////////////
        struct iphdr *ipptr;
        ipptr = (struct iphdr *)(packet_content + 14);
        struct in_addr s, d;

            gettimeofday(&tv,NULL);
            time_double=(tv.tv_sec*1000000 + tv.tv_usec - time_long)*1.000000/1000000 ;
            printf("microsecond:\t\t\t%lf\n",time_double);  //微秒

        s.s_addr=ipptr->saddr;
        d.s_addr=ipptr->daddr;
        printf("source address: \t\t%s\n", inet_ntoa(s));
        printf("destination address: \t\t%s\n", inet_ntoa(d));
        printf("total length: \t\t\t%d    \n", ntohs(ipptr->tot_len));


        number++;
        printf("NO.:\t\t\t\t%d\n",number);
        sprintf(num,"%d",number);
        sprintf(ti_do,"%lf",time_double);
        sprintf(to_le,"%d",ntohs(ipptr->tot_len));

        QStringList l;
        l<< QObject::tr(num)<<QObject::tr(ti_do) << QObject::tr(inet_ntoa(s)) << QObject::tr(inet_ntoa(d)) << QObject::tr("UDP") << QObject::tr(to_le);
        lroot = new QTreeWidgetItem(tree, l);

        //////////////////////////////////////////////////////////////////////////////////
        /// \brief printf
        ///
        inse = (Node*)malloc(sizeof(Node));

        printf("Payload:\t\t\t");
        for (i = 0; i < pcap_header->len; i++) {
            if (isprint(packet_content[i])){
                printf("%c ", packet_content[i]);
                inse->payloadsrc[i]=packet_content[i];
            }
            else{
                printf(". ");
                inse->payloadsrc[i]='.';
            }

            if ((i % 16 == 0 && i != 0) || i == pcap_header->len-1)  //every 16 a row
                printf("\n\t\t\t\t");
        }

        inse->payloadsrc[i]='\0';

        printf("\nPayload hex:\t\t\t");
        for (i = 0; i < pcap_header->len; i++) {
            printf("%x ", packet_content[i]);
            inse->payloadhex[i]=packet_content[i];
            if ((i % 16 == 0 && i != 0) || i == pcap_header->len-1) //every 16 a row
                printf("\n\t\t\t\t");
        }
        inse->payloadhex[i]='\0';
        // 添加到链表/////////////////////////////////////////////////////////////////////////////

        inse->num=number;
        strcpy(inse->td,ti_do);
        strcpy(inse->s,inet_ntoa(s));
        strcpy(inse->d,inet_ntoa(d));
        strcpy(inse->tl,to_le);
        strcpy(inse->type,"UDP");

       // a.payloadsrc=(unsigned char*)malloc((pcap_header->len+1)*sizeof(unsigned char));
        //strcpy(a.payloadsrc,packet_content);
        //memcpy(inse->payloadsrc,packet_content,pcap_header->len+1);
        printf("\npacket_content: %s____________:\n",packet_content);
        printf("\ninse->payloadsrc: %s____________:\n",inse->payloadsrc);
        inse->next=NULL;

        li.insertlist(inse);

  //////////////////////////////////////////////////////////////////////////////////////////////////////////////////


        return;
    }

    void tcp_packet_callback(unsigned char *argument, const struct pcap_pkthdr *pcap_header,
                                const unsigned char *packet_content)
    {

        struct tcphdr *tcpptr = (struct tcphdr *)(packet_content + 14 + 20);
        unsigned int i = 0;

        printf("dest port: \t\t\t%d\n", ntohs(tcpptr->dest));

    //////////////////////////////////////////////////////////////////
       struct iphdr *ipptr;
       ipptr = (struct iphdr *)(packet_content + 14);
       struct in_addr s, d;

           gettimeofday(&tv,NULL);
           time_double=(tv.tv_sec*1000000 + tv.tv_usec - time_long)*1.000000/1000000 ;
           printf("microsecond:\t\t\t%lf\n",time_double);  //微秒

       s.s_addr=ipptr->saddr;
       d.s_addr=ipptr->daddr;
       printf("source address: \t\t%s\n", inet_ntoa(s));
       printf("destination address: \t\t%s\n", inet_ntoa(d));
       printf("total length: \t\t\t%d    \n", ntohs(ipptr->tot_len));


       number++;
       printf("NO.:\t\t\t\t%d\n",number);
       sprintf(num,"%d",number);
       sprintf(ti_do,"%lf",time_double);
       sprintf(to_le,"%d",ntohs(ipptr->tot_len));

       QStringList l;
       l<< QObject::tr(num)<<QObject::tr(ti_do) << QObject::tr(inet_ntoa(s)) << QObject::tr(inet_ntoa(d)) << QObject::tr("TCP") << QObject::tr(to_le);
       lroot = new QTreeWidgetItem(tree, l);

//////////////////////////////////////////////////////////////////////////////////      
        inse = (Node*)malloc(sizeof(Node));

        printf("Payload src:\t\t\t");
        for (i = 0; i < pcap_header->len; i++) {
            if (isprint(packet_content[i])){
                printf("%c ", packet_content[i]);
                inse->payloadsrc[i]=packet_content[i];
            }
            else{
                printf(". ");
                inse->payloadsrc[i]='.';
            }

            if ((i % 16 == 0 && i != 0) || i == pcap_header->len-1)  //every 16 a row
                printf("\n\t\t\t\t");
        }

        inse->payloadsrc[i]='\0';

        printf("\nPayload hex:\t\t\t");
        for (i = 0; i < pcap_header->len; i++) {
            printf("%x ", packet_content[i]);
            inse->payloadhex[i]=packet_content[i];
            if ((i % 16 == 0 && i != 0) || i == pcap_header->len-1) //every 16 a row
                printf("\n\t\t\t\t");
        }
        inse->payloadhex[i]='\0';

        // 添加到链表/////////////////////////////////////////////////////////////////////////////

        inse->num=number;
        strcpy(inse->td,ti_do);
        strcpy(inse->s,inet_ntoa(s));
        strcpy(inse->d,inet_ntoa(d));
        strcpy(inse->tl,to_le);
        strcpy(inse->type,"TCP");

       // a.payloadsrc=(unsigned char*)malloc((pcap_header->len+1)*sizeof(unsigned char));
        //strcpy(a.payloadsrc,packet_content);
        //memcpy(inse->payloadsrc,packet_content,pcap_header->len+1);
        inse->next=NULL;

        li.insertlist(inse);


  //////////////////////////////////////////////////////////////////////////////////////////////////////////////////



        switch(ntohs(tcpptr->dest)){
        case 80:
        //printf("http");
        http_packet_callback(argument, pcap_header, packet_content);
        break;
        case 21:
        //printf("ftp");
        ftp_packet_callback(argument, pcap_header, packet_content);
        break;
        case 20:
        //printf("ftp");
        ftp_packet_callback(argument, pcap_header, packet_content);
        break;
        default:
            break;
        }


        return;
    }

    void ip_packet_callback(unsigned char *argument, const struct pcap_pkthdr *pcap_header,
                            const unsigned char *packet_content)
    {

        struct iphdr *ipptr;
        ipptr = (struct iphdr *)(packet_content + 14);

        switch(ipptr->protocol) {
        case 6:
            printf("Protocol:\t\t\tTCP\n");
            tcp_packet_callback(argument, pcap_header, packet_content);
            break;
        case 1:
            printf("Protocol:\t\t\tICMP\n");
        icmp_packet_callback(argument, pcap_header, packet_content);
            break;
        case 17:
            printf("Protocol:\t\t\tUDP\n");
        udp_packet_callback(argument, pcap_header, packet_content);
            break;
        default:
            break;
        }

        return;
    }

    void arp_packet_callback(unsigned char *argument, const struct pcap_pkthdr *pcap_header,
                    const unsigned char *packet_content)
    {
        //printf("------ARP Protocol-------\n");
        char src_mac[100]={0};
        char des_mac[100]={0};

        struct ethhdr *ethptr;
        struct in_addr s, d;
        struct iphdr *ipptr;
        unsigned char *mac;
        unsigned int i;
        ipptr = (struct iphdr *)(packet_content + 14);
        ethptr=(struct ethhdr *)packet_content;

            gettimeofday(&tv,NULL);
            time_double=(tv.tv_sec*1000000 + tv.tv_usec - time_long)*1.000000/1000000 ;
            printf("microsecond:\t\t\t%lf\n",time_double);  //微秒


        printf("MAC source Address:");
        mac = ethptr->h_source;
        printf("\t\t%02x:%02x:%02x:%02x:%02x:%02x\n", *mac, *(mac+1), *(mac+2), *(mac+3), *(mac+4), *(mac+5));
        sprintf(src_mac,"%02x:%02x:%02x:%02x:%02x:%02x",*mac, *(mac+1), *(mac+2), *(mac+3), *(mac+4), *(mac+5));

        printf("MAC destination Address:");
        mac = ethptr->h_dest;
        printf("\t%02x:%02x:%02x:%02x:%02x:%02x\n", *mac, *(mac+1), *(mac+2), *(mac+3), *(mac+4), *(mac+5));
        sprintf(des_mac,"%02x:%02x:%02x:%02x:%02x:%02x",*mac, *(mac+1), *(mac+2), *(mac+3), *(mac+4), *(mac+5));

        printf("total length: \t\t\t%d    \n", ntohs(ipptr->tot_len));
        printf("Protocol:\t\t\tARP\n");

        number++;
        printf("NO.:\t\t\t\t%d\n",number);
        sprintf(num,"%d",number);
        sprintf(ti_do,"%lf",time_double);
        sprintf(to_le,"%d",ntohs(ipptr->tot_len));

        QStringList l;
        l<< QObject::tr(num)<<QObject::tr(ti_do) << QObject::tr(src_mac) << QObject::tr(des_mac) << QObject::tr("ARP") << QObject::tr(to_le);
        lroot = new QTreeWidgetItem(tree, l);

 //////////////////////////////////////////////////////////////////////////////////
        inse = (Node*)malloc(sizeof(Node));

        printf("Payload src:\t\t\t");
        for (i = 0; i < pcap_header->len; i++) {
            if (isprint(packet_content[i])){
                printf("%c ", packet_content[i]);
                inse->payloadsrc[i]=packet_content[i];
            }
            else{
                printf(". ");
                inse->payloadsrc[i]='.';
            }

            if ((i % 16 == 0 && i != 0) || i == pcap_header->len-1)  //every 16 a row
                printf("\n\t\t\t\t");
        }

        inse->payloadsrc[i]='\0';

        printf("\nPayload hex:\t\t\t");
        for (i = 0; i < pcap_header->len; i++) {
            printf("%x ", packet_content[i]);
            inse->payloadhex[i]=packet_content[i];
            if ((i % 16 == 0 && i != 0) || i == pcap_header->len-1) //every 16 a row
                printf("\n\t\t\t\t");
        }
        inse->payloadhex[i]='\0';
       // 添加到链表/////////////////////////////////////////////////////////////////////////////

        inse->num=number;
        strcpy(inse->td,ti_do);
        strcpy(inse->s,src_mac);
        strcpy(inse->d,des_mac);
        strcpy(inse->tl,to_le);
        strcpy(inse->type,"ARP");

       // a.payloadsrc=(unsigned char*)malloc((pcap_header->len+1)*sizeof(unsigned char));
        //strcpy(a.payloadsrc,packet_content);
        //memcpy(inse->payloadsrc,packet_content,pcap_header->len+1);
        inse->next=NULL;

        li.insertlist(inse);
        //strcpy(a.s,src_mac);
        //strcpy(a.d,des_mac);

 //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        return;
    }
    //1    2  &hdr     3u_char packet
    void ethernet_packet_callback(unsigned char *argument, const struct pcap_pkthdr *pcap_header,const unsigned char *packet_content)
    {
        struct ethhdr *ethptr;
        struct iphdr *ipptr;
        unsigned char *mac;

        ethptr=(struct ethhdr *)packet_content;
        printf("\n----ethernet protocol-----\n");//(physical layer)
        //number++;
        //printf("NO.:\t\t\t\t%d\n",number);
      //  printf("MAC source Address:");
        mac = ethptr->h_source;
      //  printf("\t\t%02x:%02x:%02x:%02x:%02x:%02x\n", *mac, *(mac+1), *(mac+2), *(mac+3), *(mac+4), *(mac+5));
      //  printf("MAC destination Address:");
        mac = ethptr->h_dest;
       // printf("\t%02x:%02x:%02x:%02x:%02x:%02x\n", *mac, *(mac+1), *(mac+2), *(mac+3), *(mac+4), *(mac+5));
        //printf("protocol: %04x\n", ntohs(ethptr->h_proto));

        switch(ntohs(ethptr->h_proto)) {
        case 0x0800:
            ip_packet_callback(argument,pcap_header,packet_content);
            break;
        case 0x0806:
            arp_packet_callback(argument,pcap_header,packet_content);
            break;
        default:
            break;

        }

        return;
    }



    /////////////////////////////////////////////////////////////////////////////////
    /// \brief tree
    /////////////////////////////////////////////////////////////////////////////////////////
    /// ////////////////////////////////////////////////////////////////////////////
    //QTreeWidget *tree = new QTreeWidget;   //global

    QPushButton *pauseee = new QPushButton(QObject::tr("暂停"));
    QPushButton *restart = new QPushButton(QObject::tr("启动"));
    //QLabel *label3 = new QLabel;
    QTextEdit *edt_hex= new QTextEdit;
    QTextEdit *edt_src= new QTextEdit;


    void dis(){
        ///////////////////////////////////////////////////////
        QFont tree_font;
        tree_font.setPointSize(20);

       // QTreeWidget *tree = new QTreeWidget;
        tree->setFont(tree_font);
        tree->setFixedHeight(700);
        tree->setFixedWidth(1350);

        //tree->setSelectionMode(QAbstractItemView::ExtendedSelection);
        tree->setColumnCount(6);


        QStringList headers;


        char ai[100][100]={0};
        char bi[100]="bbbbbb";
        strcpy(ai[0],bi);

 //      char cc[100];
//       char dd[100];
 //       sprintf(cc,"%d",number);
 //       number++;
//        sprintf(dd,"%d",number);

        headers << QObject::tr("序号") <<QObject::tr("时间")<<QObject::tr("源")<<QObject::tr("目的")<<QObject::tr("协议类型")<<QObject::tr("长度");
        tree->setHeaderLabels(headers);



/*
        tree->setColumnWidth(0, 100);  //设置列宽
        tree->setColumnWidth(1, 1000);
        tree->setColumnWidth(2, 1000);
        tree->setColumnWidth(3, 600);
        tree->setColumnWidth(4, 500);
        tree->setColumnWidth(5, 500);

            QStringList zhangsan;
            zhangsan << QObject::tr("cc")<<QString("dd") << QObject::tr("dd") << QObject::tr("192.1") << QObject::tr("TCP") << QObject::tr("64");
            QTreeWidgetItem *zhangsanroot = new QTreeWidgetItem(tree, zhangsan);


         //   number++;
           // sprintf(cc,"%d",number);
            //number++;
            //sprintf(dd,"%d",number);

            QStringList pppp;
            pppp << QObject::tr(cc)<<QObject::tr(dd) << QObject::tr("192.1") << QObject::tr("192.1") << QObject::tr("TCP") << QObject::tr("64");
            QTreeWidgetItem *lisiroot = new QTreeWidgetItem(tree, pppp);

*/

/////////////////////////////////////////////////////////////////////////////////////////

            pcap_t *pt;
            char *dev;
            char errbuf[128];
            struct bpf_program fp;
            bpf_u_int32 maskp, netp;
            int ret,i=0,inum;
            int pcap_time_out = 5;
            char filter[128] = {0};
            //unsigned char *packet;//global
            //struct pcap_pkthdr hdr;//global
            pcap_if_t *alldevs;


            dev="eth0";


            printf("dev: %s\n", dev);
            ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
            if(ret == -1) {
                fprintf(stderr,"%s\n", errbuf);
                return;
            }

            pt = pcap_open_live(dev, BUFSIZ, 1, pcap_time_out, errbuf);
            if(pt == NULL) {
                fprintf(stderr,"open error :%s\n", errbuf);
                return;
            }

            if(pcap_compile(pt, &fp, filter, 0, netp) == -1) {
                fprintf(stderr, "compile error\n");
                return ;
            }

            if(pcap_setfilter(pt, &fp) == -1) {
                fprintf(stderr,"setfilter error\n");
                return ;
            }

            //before pcap_loop ,initial time 'time_long'
            gettimeofday(&tv,NULL);
            //printf("microsecond:%ld\n",tv.tv_sec*1000000 + tv.tv_usec);  //微秒
            time_long=tv.tv_sec*1000000 + tv.tv_usec;


            //pcap_loop(pt, -1, ethernet_packet_callback, NULL);

           // QTreeWidgetItem *lroot;//global
           // QTreeWidgetItem *current;
    while(1){
            while(stopped){
                packet=(unsigned char *)pcap_next(pt,&hdr);
                if(packet==NULL)
                              continue;
                else{
                              //printf("get a packet/n");
                        ethernet_packet_callback(NULL,&hdr,packet);
                        //currentItem(current);
                        //sleep(1);
                        //if(stopped==true)
                            //break;
                }
            }
           sleep(1);
    }

            pcap_close(pt);
    }


public slots:
    void stop(){
            stopped=false;
            pauseee->setText("已暂停");
            restart->setText("继续");
      }

    void begin(){
        stopped=true;
        pauseee->setText("暂停");
        restart->setText("启动");

    }

    void showpackage(QTreeWidgetItem*item,int ccc){     //show src & hex

        //struct pcap_pkthdr hh=hdr;// length
       // unsigned char *p=packet;//content



////////////////////////////////////////////////////////
        QString str = item->text(0);
        QByteArray ba1 = str.toLatin1();
        const char *str1 = ba1.data();
        int i = atoi (str1);printf("int:%d\n",i);printf("str:%s\n",str1);

        fi=li.find(i);


       // QString ggg="";
       // ggg=ggg.append(fi->payloadsrc);
        //ggg=ggg.append(*packet);
        //ggg=ggg.append(fi->type);

        char food[100000];
        char food_hex[100000];
        char food_hexout[100000];

        int length=atoi(fi->tl);

        //printf("packet***************\n%s\n",packet);
        //printf("fi->payloadsrc***************\n%s\n",fi->payloadsrc);

        memcpy(food,fi->payloadsrc,length+1);
        printf("food:***************\n%s\n",food);



        memcpy(food_hex,fi->payloadhex,length+1);
        printf("food_hex:***************\n%s\n",food_hex);

        fun(food_hex,food_hexout,length+1);

        QString ggg1="";
        ggg1=ggg1.append(food);

        QString ggg2="";
        ggg2=ggg2.append(food_hexout);
        //memcpy(inse->payloadsrc,packet_content,pcap_header->len+1);

        edt_hex->setPlainText(ggg2);
        edt_src->setPlainText(ggg1);

    }

protected:
    void run(){
        dis();
    }

private:
    bool stopped=false;

};
#endif // MAINWINDOW_H
