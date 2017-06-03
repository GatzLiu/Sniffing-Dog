#-------------------------------------------------
#
# Project created by QtCreator 2016-12-28T01:56:19
#
#-------------------------------------------------

QT       += core gui
LIBS+=-L/usr/local/lib -lpcap
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = net8
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp

HEADERS  += mainwindow.h

FORMS    += mainwindow.ui
