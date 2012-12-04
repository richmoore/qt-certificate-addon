
QT += network
TEMPLATE = lib
TARGET = certificate

LIBS += -lgnutls
DEFINES += QT_CERTIFICATE_LIB


# Input
SOURCES += certificatebuilder.cpp \
           certificaterequestbuilder.cpp \
           certificaterequest.cpp \
           keybuilder.cpp \
           utils.cpp




