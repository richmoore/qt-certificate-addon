#include <gnutls/gnutls.h>

#include <QByteArray>
#include <QSslKey>

#include "utils_p.h"

QT_BEGIN_NAMESPACE_CERTIFICATE

void ensure_gnutls_init()
{
    static bool done = false;

    // TODO: protect with a mutex
    if (!done) {
        gnutls_global_init();
    }
}

int qsslkey_to_key(const QSslKey &qkey, gnutls_x509_privkey_t key)
{
    QByteArray buf(qkey.toPem());

    // Setup a datum
    gnutls_datum_t buffer;
    buffer.data = (unsigned char *)(buf.data());
    buffer.size = buf.size();

    return gnutls_x509_privkey_import(key, &buffer, GNUTLS_X509_FMT_PEM);
}

QT_END_NAMESPACE_CERTIFICATE
