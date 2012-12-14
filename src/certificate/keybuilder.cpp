
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

/*!
  Generates a new key using the specified algorithm and strength. The algorithm
  will generally be RSA. The various strengths allow you to specify the trade-off
  between the security of the key and the time involved in creating it.

  Note that this method can take a considerable length of time to execute, so in
  gui applications it should be run in a worker thread.
 */
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
    default:
        qWarning("Unhandled strength %d passed to generate", uint(strength));
        sec = GNUTLS_SEC_PARAM_NORMAL;
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

    QSslKey qkey = key_to_qsslkey(key, algo, &errno);
    if (GNUTLS_E_SUCCESS != errno) {
        qWarning("Failed to convert key to bytearray %s", gnutls_strerror(errno));
        gnutls_x509_privkey_deinit(key);
        return QSslKey();
    }
    
    return qkey;
}

QT_END_NAMESPACE_CERTIFICATE
