#include <QFile>

#include "randomgenerator.h"

QT_BEGIN_NAMESPACE_CERTIFICATE

/*!
  \class RandomGenerator
  \brief The RandomGenerator class is a tool for creating hard random numbers.

  The RandomGenerator class provides a source of secure random numbers using
  the system's random source (/dev/random on UNIX). The numbers are suitable
  for uses such as certificate serial numbers.
*/

/*!
  Generates a set of random bytes of the specified size. In order to allow
  these to be conveniently used as serial numbers, this method ensures that
  the value returned is positive (ie. that the first bit is 0). This means
  that you get one less bit of entropy than requested, but avoids
  interoperability issues.
 */
QByteArray RandomGenerator::getPositiveBytes(int size)
{
    // TODO: Steal win32 version from peppe's change

#if defined(Q_OS_UNIX)
    QFile randomDevice(QLatin1String("/dev/random"));
    randomDevice.open(QIODevice::ReadOnly|QIODevice::Unbuffered);

    QByteArray result = randomDevice.read(size);
    if (result.size() != size)
        return QByteArray(); // We return what's asked for or not at all

    // Clear the top bit to ensure the number is positive
    char *data = result.data();
    *data = *data & 0x07f;

    return result;
#endif
    return QByteArray();
}

QT_END_NAMESPACE_CERTIFICATE
