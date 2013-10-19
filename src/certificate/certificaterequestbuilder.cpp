#include <QIODevice>

#include "certificaterequest_p.h"
#include "utils_p.h"

#include "certificaterequestbuilder_p.h"

QT_BEGIN_NAMESPACE_CERTIFICATE

/*!
  \class CertificateRequestBuilder
  \brief The CertificateRequestBuilder class is a tool for creating certificate
  signing requests.
*/

CertificateRequestBuilder::CertificateRequestBuilder()
    : d(new CertificateRequestBuilderPrivate)
{
    ensure_gnutls_init();

    gnutls_x509_crq_init(&d->crq);
    d->errno = GNUTLS_E_SUCCESS;
}

CertificateRequestBuilder::~CertificateRequestBuilder()
{
    gnutls_x509_crq_deinit(d->crq);
    delete d;
}

/*!
  Returns the last error that occurred when using this object. The values
  used are those of gnutls. If there has not been an error then it is
  guaranteed to be 0.
 */
int CertificateRequestBuilder::error() const
{
    return d->errno;
}

/*!
  Returns a string describing the last error that occurred when using
  this object.
 */
QString CertificateRequestBuilder::errorString() const
{
    return QString::fromUtf8(gnutls_strerror(d->errno));
}

/*!
  Set the version of the certificate signing request. This should
  generally be set to 1.
 */
bool CertificateRequestBuilder::setVersion(int version)
{
    d->errno = gnutls_x509_crq_set_version(d->crq, version);
    return GNUTLS_E_SUCCESS == d->errno;
}

/*!
  Returns the version of the certificate signing request.
 */
int CertificateRequestBuilder::version() const
{
    int ver = gnutls_x509_crq_get_version(d->crq);
    if (ver < 0)
        d->errno = ver;
    return ver;
}

/*!
  Sets the key that will be used for the reqest.
 */
bool CertificateRequestBuilder::setKey(const QSslKey &qkey)
{
    gnutls_x509_privkey_t key = qsslkey_to_key(qkey, &d->errno);
    if (GNUTLS_E_SUCCESS != d->errno) {
        gnutls_x509_privkey_deinit(key);
        return false;
    };

    d->errno = gnutls_x509_crq_set_key(d->crq, key);

    gnutls_x509_privkey_deinit(key);

    return GNUTLS_E_SUCCESS == d->errno;
}

bool CertificateRequestBuilder::addNameEntry(EntryType type, const QByteArray &value)
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
        return false;
    }

    return addNameEntry(oid, value);
}

bool CertificateRequestBuilder::addNameEntry(const QByteArray &oid, const QByteArray &value, bool raw)
{
    d->errno = gnutls_x509_crq_set_dn_by_oid(d->crq, oid.constData(), raw,
                                             value.constData(), qstrlen(value.constData()));
    return GNUTLS_E_SUCCESS == d->errno;   
}

/*!
  Signs the request with the specified key and returns the signed request.
 */
CertificateRequest CertificateRequestBuilder::signedRequest(const QSslKey &qkey)
{
    CertificateRequest result;

    gnutls_x509_privkey_t key = qsslkey_to_key(qkey, &d->errno);
    if (GNUTLS_E_SUCCESS != d->errno) {
        gnutls_x509_privkey_deinit(key);
        return result;
    };

    d->errno = gnutls_x509_crq_sign2(d->crq, key, GNUTLS_DIG_SHA1, 0);
    gnutls_x509_privkey_deinit(key);

    if (GNUTLS_E_SUCCESS != d->errno)
        return result;

    gnutls_x509_crq_t crqsave = result.d->crq;
    result.d->crq = d->crq;
    d->crq = crqsave;

    return result;
}

QT_END_NAMESPACE_CERTIFICATE
