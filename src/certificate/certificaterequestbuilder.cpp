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

/*!
  Returns the list of attributes that are present in this requests
  distinguished name. The attributes are returned as OIDs.
 */
QList<QByteArray> CertificateRequestBuilder::nameEntryAttributes()
{
    QList<QByteArray> result;

    int index = 0;
    do {
        QByteArray buffer(1024, 0);
        size_t size = buffer.size();

        d->errno = gnutls_x509_crq_get_dn_oid(d->crq, index, buffer.data(), &size);

        if (GNUTLS_E_SUCCESS == d->errno) {
            buffer.resize(size);
            result << buffer;
        }
        index++;
    } while(GNUTLS_E_SUCCESS == d->errno);

    return result;
}

/*!
  Returns the list of entries for the attribute specified.
 */
QStringList CertificateRequestBuilder::nameEntryInfo(Certificate::EntryType attribute)
{
    return nameEntryInfo(entrytype_to_oid(attribute));
}

/*!
  Returns the list of entries for the attribute specified by the oid.
 */
QStringList CertificateRequestBuilder::nameEntryInfo(const QByteArray &oid)
{
    QStringList result;
    if (oid.isNull())
        return result;

    int index = 0;
    do {
        QByteArray buffer(1024, 0);
        size_t size = buffer.size();

        d->errno = gnutls_x509_crq_get_dn_by_oid(d->crq, oid.constData(), index, false, buffer.data(), &size);

        if (GNUTLS_E_SUCCESS == d->errno)
            result << QString::fromUtf8(buffer);

        index++;
    } while(GNUTLS_E_SUCCESS == d->errno);

    return result;
}

bool CertificateRequestBuilder::addNameEntry(Certificate::EntryType type, const QByteArray &value)
{
    QByteArray oid = entrytype_to_oid(type);
    if (oid.isNull())
        return false;

    return addNameEntry(oid, value);
}

bool CertificateRequestBuilder::addNameEntry(const QByteArray &oid, const QByteArray &value, bool raw)
{
    d->errno = gnutls_x509_crq_set_dn_by_oid(d->crq, oid.constData(), raw,
                                             value.constData(), qstrlen(value.constData()));
    return GNUTLS_E_SUCCESS == d->errno;
}

#if QT_VERSION >= 0x050000
bool CertificateRequestBuilder::addSubjectAlternativeNameEntry(QSsl::AlternativeNameEntryType qtype, const QByteArray &value)
{
    gnutls_x509_subject_alt_name_t type = qssl_altnameentrytype_to_altname(qtype);

    d->errno = gnutls_x509_crq_set_subject_alt_name(d->crq, type, value.constData(), value.size(), GNUTLS_FSAN_APPEND);
    return GNUTLS_E_SUCCESS == d->errno;
}
#else
bool CertificateRequestBuilder::addSubjectAlternativeNameEntry(QSsl::AlternateNameEntryType qtype, const QByteArray &value)
{
    gnutls_x509_subject_alt_name_t type = qssl_altnameentrytype_to_altname(qtype);

    d->errno = gnutls_x509_crq_set_subject_alt_name(d->crq, type, value.constData(), value.size(), GNUTLS_FSAN_APPEND);
    return GNUTLS_E_SUCCESS == d->errno;
}
#endif

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
