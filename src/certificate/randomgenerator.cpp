#include <QFile>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include "randomgenerator.h"

QT_BEGIN_NAMESPACE_CERTIFICATE

/*!
  \class RandomGenerator
  \brief The RandomGenerator class is a tool for creating hard random numbers.

  The RandomGenerator class provides a source of secure random numbers using
  the gnutls rnd API. The numbers are suitable for uses such as certificate
  serial numbers.
*/

/*!
  Generates a set of random bytes of the specified size. In order to allow
  these to be conveniently used as serial numbers, this method ensures that
  the value returned is positive (ie. that the first bit is 0). This means
  that you get one less bit of entropy than requested, but avoids
  interoperability issues.

  Note that this method will either return the number of bytes requested,
  or a null QByteArray. It will never return a smaller number.
 */
QByteArray RandomGenerator::getPositiveBytes(int size)
{
    QByteArray result(size, 0);

    int errno = gnutls_rnd(GNUTLS_RND_RANDOM, result.data(), size);
    if (GNUTLS_E_SUCCESS != errno)
        return QByteArray();

    // Clear the top bit to ensure the number is positive
    char *data = result.data();
    *data = *data & 0x07f;

    return result;
}

QT_END_NAMESPACE_CERTIFICATE
