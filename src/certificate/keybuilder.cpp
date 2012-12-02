
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "utils_p.h"

#include "keybuilder.h"

QT_BEGIN_NAMESPACE_CERTIFICATE

/*!
  \class KeyBuilder
  \brief The KeyBuilder class is a tool for creating QSslKeys.

  The KeyBuilder class provides an easy way to generate a new private
  key for an X.509 certificate.
*/

static QByteArray key_to_bytearray(gnutls_x509_privkey_t key, gnutls_x509_crt_fmt_t format, int *errno)
{
    QByteArray ba(4096, 0);
    size_t size = ba.size();

    *errno = gnutls_x509_privkey_export(key, format, ba.data(), &size);

    if (GNUTLS_E_SUCCESS != *errno)
        return QByteArray();

    ba.resize(size); // size has now been updated
    return ba;

}

QSslKey KeyBuilder::generate( QSsl::KeyAlgorithm algo, KeyStrength strength )
{
    ensure_gnutls_init();

    gnutls_sec_param_t sec;
    switch(strength) {
    case StrengthLow:
        sec = GNUTLS_SEC_PARAM_LOW;
        break;
    case StrengthNormal:
        sec = GNUTLS_SEC_PARAM_NORMAL;
        break;
    case StrengthHigh:
        sec = GNUTLS_SEC_PARAM_HIGH;
        break;
    case StrengthUltra:
        sec = GNUTLS_SEC_PARAM_ULTRA;
        break;
    }

    uint bits = gnutls_sec_param_to_pk_bits((algo == QSsl::Rsa) ? GNUTLS_PK_RSA : GNUTLS_PK_DSA, sec);
    gnutls_x509_privkey_t key;
    gnutls_x509_privkey_init(&key);

    int errno = gnutls_x509_privkey_generate(key, (algo == QSsl::Rsa) ? GNUTLS_PK_RSA : GNUTLS_PK_DSA, bits, 0);
    if (GNUTLS_E_SUCCESS != errno) {
        qWarning("Failed to generate key %s", gnutls_strerror(errno));
        gnutls_x509_privkey_deinit(key);
        return QSslKey();
    }

    QByteArray ba = key_to_bytearray(key, GNUTLS_X509_FMT_PEM, &errno);
    gnutls_x509_privkey_deinit(key);

    if (GNUTLS_E_SUCCESS != errno) {
        qWarning("Failed to convert key to bytearray %s", gnutls_strerror(errno));
        return QSslKey();
    }
    

    return QSslKey(ba, algo, QSsl::Pem);
}

QT_END_NAMESPACE_CERTIFICATE
