// -*- c++ -*-

#ifndef RANDOMGENERATOR_H
#define RANDOMGENERATOR_H

#include <QByteArray>

#include "certificate_global.h"

QT_BEGIN_NAMESPACE_CERTIFICATE

class Q_CERTIFICATE_EXPORT RandomGenerator
{
public:
    static QByteArray getPositiveBytes(int size);

private:
    RandomGenerator() {}
    ~RandomGenerator() {}
};

QT_END_NAMESPACE_CERTIFICATE

#endif // RANDOMGENERATOR_H

