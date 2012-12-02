#include <QByteArray>
#include <QIODevice>

#include "utils_p.h"

#include "certificaterequest_p.h"

QT_BEGIN_NAMESPACE_CERTIFICATE

/*!
  \class CertificateRequest
  \brief The CertificateRequest class provides a convenient interface for an X.509
  certificate signing request.
*/

/*!
  \internal
  Convert a crq to a PEM or DER encoded QByteArray.
 */
static QByteArray request_to_bytearray(gnutls_x509_crq_t crq, gnutls_x509_crt_fmt_t format, int *errno)
{
    QByteArray ba(4096, 0);
    size_t size = ba.size();

    *errno = gnutls_x509_crq_export(crq, format, ba.data(), &size);

    if (GNUTLS_E_SUCCESS != *errno)
        return QByteArray();

    ba.resize(size); // size has now been updated
    return ba;
}

CertificateRequestPrivate::CertificateRequestPrivate()
    : null(true)
{
    ensure_gnutls_init();

    gnutls_x509_crq_init(&crq);
    errno = GNUTLS_E_SUCCESS;
}

CertificateRequestPrivate::~CertificateRequestPrivate()
{
    gnutls_x509_crq_deinit(crq);
}

/*!
  Create a null CertificateRequest.
 */
CertificateRequest::CertificateRequest()
    : d(new CertificateRequestPrivate)
{
}

/*!
  Create a CertificateRequest that is a copy of other.
 */
CertificateRequest::CertificateRequest(const CertificateRequest &other)
    : d(other.d)
{
}

/*!
  Load a CertificateRequest from the specified QIODevice using the specified format.
 */
CertificateRequest::CertificateRequest(QIODevice *io, QSsl::EncodingFormat format)
    : d(new CertificateRequestPrivate)
{
    QByteArray buf = io->readAll();

    // Setup a datum
    gnutls_datum_t buffer;
    buffer.data = (unsigned char *)(buf.data());
    buffer.size = buf.size();

    d->errno = gnutls_x509_crq_import(d->crq, &buffer, (QSsl::Pem == format) ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER);
    if (GNUTLS_E_SUCCESS == d->errno)
        d->null = false;
}

/*!
  Clean up.
 */
CertificateRequest::~CertificateRequest()
{
}

/*!
  Returns true if this CertificateRequest is null (uninitialised).
 */
bool CertificateRequest::isNull() const
{
    return d->null;
}

/*!
  Returns the last error that occurred when using this object. The values
  used are those of gnutls. If there has not been an error then it is
  guaranteed to be 0.
 */
int CertificateRequest::error() const
{
    return d->errno;
}

/*!
  Returns a string describing the last error that occurred when using
  this object.
 */
QString CertificateRequest::errorString() const
{
    return QString::fromUtf8(gnutls_strerror(d->errno));
}

/*!
  Returns a QByteArray containing this request encoded as PEM.
 */
QByteArray CertificateRequest::toPem()
{
    return request_to_bytearray(d->crq, GNUTLS_X509_FMT_PEM, &d->errno);
}

/*!
  Returns a QByteArray containing this request encoded as DER.
 */
QByteArray CertificateRequest::toDer()
{
    return request_to_bytearray(d->crq, GNUTLS_X509_FMT_DER, &d->errno);
}

QT_END_NAMESPACE_CERTIFICATE
