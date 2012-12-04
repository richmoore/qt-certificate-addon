#include <gnutls/gnutls.h>

#include <QByteArray>
#include <QSslKey>
#include <QSslCertificate>

#include "utils_p.h"

QT_BEGIN_NAMESPACE_CERTIFICATE

using namespace Certificate;

void ensure_gnutls_init()
{
    static bool done = false;

    // TODO: protect with a mutex
    if (!done) {
        gnutls_global_init();
        done = true;
    }
}

QByteArray entrytype_to_oid(Certificate::EntryType type)
{
    QByteArray oid;

    // TODO: More common name entry types

    switch(type) {
    case EntryCountryName:
        oid = QByteArray(GNUTLS_OID_X520_COUNTRY_NAME);
        break;
    case EntryOrganizationName:
        oid = QByteArray(GNUTLS_OID_X520_ORGANIZATION_NAME);
        break;
    case EntryOrganizationalUnitName:
        oid = QByteArray(GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME);
        break;
    case EntryCommonName:
        oid = QByteArray(GNUTLS_OID_X520_COMMON_NAME);
        break;
    case EntryLocalityName:
        oid = QByteArray(GNUTLS_OID_X520_LOCALITY_NAME);
        break;
    case EntryStateOrProvinceName:
        oid = QByteArray(GNUTLS_OID_X520_STATE_OR_PROVINCE_NAME);
        break;
    case EntryEmail:
        oid = QByteArray(GNUTLS_OID_PKCS9_EMAIL);
        break;
    default:
        qWarning("Unhandled name entry type %d", int(type));
    }

    return oid;
}

gnutls_x509_privkey_t qsslkey_to_key(const QSslKey &qkey, int *errno)
{
    gnutls_x509_privkey_t key;

    *errno = gnutls_x509_privkey_init(&key);
    if (GNUTLS_E_SUCCESS != *errno)
        return 0;

    QByteArray buf(qkey.toPem());

    // Setup a datum
    gnutls_datum_t buffer;
    buffer.data = (unsigned char *)(buf.data());
    buffer.size = buf.size();

    *errno = gnutls_x509_privkey_import(key, &buffer, GNUTLS_X509_FMT_PEM);
    return key;
}

gnutls_x509_crt_t qsslcert_to_crt(const QSslCertificate &qcert, int *errno)
{
    gnutls_x509_crt_t cert;

    *errno = gnutls_x509_crt_init(&cert);
    if (GNUTLS_E_SUCCESS != *errno)
        return 0;

    QByteArray buf(qcert.toPem());

    // Setup a datum
    gnutls_datum_t buffer;
    buffer.data = (unsigned char *)(buf.data());
    buffer.size = buf.size();

    // Import the cert
    *errno = gnutls_x509_crt_import(cert, &buffer, GNUTLS_X509_FMT_PEM);
    return cert;
}

QSslCertificate crt_to_qsslcert(gnutls_x509_crt_t crt, int *errno)
{
    QByteArray ba(4096, 0);
    size_t size = ba.size();

    *errno = gnutls_x509_crt_export(crt, GNUTLS_X509_FMT_PEM, ba.data(), &size);
    if (GNUTLS_E_SUCCESS != *errno)
        return QSslCertificate();

    return QSslCertificate(ba);
}

QSslKey key_to_qsslkey(gnutls_x509_privkey_t key, QSsl::KeyAlgorithm algo, int *errno)
{
    QByteArray ba(4096, 0);
    size_t size = ba.size();

    *errno = gnutls_x509_privkey_export(key, GNUTLS_X509_FMT_PEM, ba.data(), &size);
    if (GNUTLS_E_SUCCESS != *errno)
        return QSslKey();

    return QSslKey(ba, algo);
}

QT_END_NAMESPACE_CERTIFICATE
