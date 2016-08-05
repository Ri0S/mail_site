TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.c

LIBS += -lnetfilter_queue

DISTFILES += \
    mal_site.txt
