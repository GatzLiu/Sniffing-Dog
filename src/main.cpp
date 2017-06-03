#include "mainwindow.h"



int main(int argc, char *argv[])
{

       QApplication a(argc, argv);
       QPushButton *endup = new QPushButton(QObject::tr("退出"));


       Mythread my;
       my.start();

       QFont button_font;
       button_font.setPointSize(22);

       my.pauseee->setFont(button_font);
       my.pauseee->setFixedSize(300,110);
       endup->setFont(button_font);
       endup->setFixedSize(300,110);
       my.restart->setFont(button_font);
       my.restart->setFixedSize(300,110);

       QFont lbl_font;
       lbl_font.setPointSize(28);
       //my.label3->setFont(lbl_font);  //设置字体大小
      // my.label3->setFixedWidth(1000);
       //my.label3->setFixedHeight(100);

       QFont edt_font;
       edt_font.setPointSize(18);
       my.edt_hex->setFont(edt_font);
       my.edt_hex->setReadOnly(true);
       my.edt_hex->setFixedSize(660,250);

       my.edt_src->setFont(edt_font);
       my.edt_src->setReadOnly(true);
       my.edt_src->setFixedSize(660,250);
    //   label->setGeometry(QRect(20, 20, 150, 30)); //设置大小和位置
    //   label->setFrameStyle(QFrame::Panel | QFrame::Sunken); //设置外观
    // label->setText("Hello World.");

       QVBoxLayout *updown= new QVBoxLayout;//最上面
       updown->addWidget(my.tree);

       QHBoxLayout *edt_lr=new QHBoxLayout;//水平两个显示框
       edt_lr->addWidget(my.edt_hex);
       edt_lr->addWidget(my.edt_src);


       QHBoxLayout *leftright=new QHBoxLayout;//水平三个按钮
       leftright->addWidget(my.restart);
       leftright->addWidget(my.pauseee);
       leftright->addWidget(endup);


       QVBoxLayout *mainlayout = new QVBoxLayout;
       mainlayout->addLayout(updown);
       mainlayout->addLayout(edt_lr);
       mainlayout->addLayout(leftright);



      // QObject::connect(listWidget, SIGNAL(currentTextChanged(QString)), label, SLOT(setText(QString)));
      // QObject::connect(my.tree, SIGNAL(itemClicked(QTreeWidgetItem*,int)), &my, SLOT(showpackage()));
       QObject::connect(my.pauseee, SIGNAL(clicked()), &my, SLOT(stop()));
       QObject::connect(my.restart, SIGNAL(clicked()), &my, SLOT(begin()));
       QObject::connect(my.tree, SIGNAL(itemClicked(QTreeWidgetItem*,int)), &my, SLOT(showpackage(QTreeWidgetItem*,int)));
       QObject::connect(endup, SIGNAL(clicked()), &a ,SLOT(quit()));

       mainlayout->setSpacing(10);

       QWidget *widget = new QWidget;
       widget->setLayout(mainlayout);
       widget->setWindowTitle(QObject::tr("System"));
       widget->show();





       return a.exec();
}
