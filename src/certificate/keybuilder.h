// -*- c++ -*-

#ifndef KEYBUILDER_H
#define KEYBUILDER_H

#include <QtNetwork/QSslKey>
#include <QtNetwork/QSsl>

#include "certificate_global.h"

QT_BEGIN_NAMESPACE_CERTIFICATE

class Q_CERTIFICATE_EXPORT KeyBuilder
{
public:
    enum KeyStrength {
        StrengthLow,
        StrengthNormal,
        StrengthHigh,
        StrengthUltra
    };

    static QSslKey generate( QSsl::KeyAlgorithm algo, KeyStrength strength );

private:
    KeyBuilder() {}
    ~KeyBuilder() {}

private:
    struct KeyBuilderPrivate *d;
};

QT_END_NAMESPACE_CERTIFICATE

#endif // KEYBUILDER_H
