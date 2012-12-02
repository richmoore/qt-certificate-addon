TEMPLATE = app
TARGET = create_certificate

QT += network

# TODO: Remove the need for -lgnutls by fixing the lib init call
LIBS    += -Wl,-rpath,../../src/certificate -L../../src/certificate -lcertificate
INCLUDEPATH += ../../src/certificate

SOURCES = main.cpp
