#include <QDateTime>
#include <QSslKey>

extern "C" {
#include <gnutls/abstract.h>
};

#include "certificaterequest_p.h"
#include "utils_p.h"

#include "certificatebuilder_p.h"

QT_BEGIN_NAMESPACE_CERTIFICATE

/*!
  \class CertificateBuilder
  \brief The CertificateBuilder class is a tool for creating X.509 certificates.
*/

CertificateBuilder::CertificateBuilder()
    : d(new CertificateBuilderPrivate)
{
    ensure_gnutls_init();
    d->errno = gnutls_x509_crt_init(&d->crt);
}

CertificateBuilder::~CertificateBuilder()
{
    gnutls_x509_crt_deinit(d->crt);
    delete d;
}

/*!
  Returns the last error that occurred when using this object. The values
  used are those of gnutls. If there has not been an error then it is
  guaranteed to be 0.
 */
int CertificateBuilder::error() const
{
    return d->errno;
}

/*!
  Returns a string describing the last error that occurred when using
  this object.
 */
QString CertificateBuilder::errorString() const
{
    return QString::fromUtf8(gnutls_strerror(d->errno));
}

/*!
  Set the request that the certificate will be generated from.
 */
bool CertificateBuilder::setRequest(const CertificateRequest &crq)
{
    d->errno = gnutls_x509_crt_set_crq(d->crt, crq.d->crq);
    return GNUTLS_E_SUCCESS == d->errno;
}

/*!
  Set the version of the X.509 certificate. In general the version will be 3.
 */
bool CertificateBuilder::setVersion(int version)
{
    d->errno = gnutls_x509_crt_set_version(d->crt, version);
    return GNUTLS_E_SUCCESS == d->errno;
}

/*!
  Set the serial number of the certificate. This should be a random value
  containing a large amount of entropy.
 */
bool CertificateBuilder::setSerial(const QByteArray &serial)
{
    d->errno = gnutls_x509_crt_set_serial(d->crt, serial.constData(), serial.size());
    return GNUTLS_E_SUCCESS == d->errno;
}

/*!
  Set the time at which the certificate will become valid.
 */
bool CertificateBuilder::setActivationTime(const QDateTime &date)
{
    d->errno = gnutls_x509_crt_set_activation_time(d->crt, date.toTime_t());
    return GNUTLS_E_SUCCESS == d->errno;
}

/*!
  Set the time after which the certificate is no longer valid.
 */
bool CertificateBuilder::setExpirationTime(const QDateTime &date)
{
    d->errno = gnutls_x509_crt_set_expiration_time(d->crt, date.toTime_t());
    return GNUTLS_E_SUCCESS == d->errno;
}

bool CertificateBuilder::copyRequestExtensions(const CertificateRequest &crq)
{
    d->errno = gnutls_x509_crt_set_crq_extensions(d->crt, crq.d->crq);
    return GNUTLS_E_SUCCESS == d->errno;
}

bool CertificateBuilder::setBasicConstraints(bool ca, int pathLength)
{
    d->errno = gnutls_x509_crt_set_basic_constraints (d->crt, ca, pathLength);
    return GNUTLS_E_SUCCESS == d->errno;
}

bool CertificateBuilder::addKeyPurpose(KeyPurpose purpose, bool critical)
{
    QByteArray ba;

    switch(purpose) {
    case PurposeWebServer:
        ba = QByteArray(GNUTLS_KP_TLS_WWW_SERVER);
        break;
    default:
        qWarning("Unknown Purpose %d", int(purpose));
        return false;
    }

    return addKeyPurpose(ba, critical);
}

bool CertificateBuilder::addKeyPurpose(const QByteArray &oid, bool critical)
{
    d->errno = gnutls_x509_crt_set_key_purpose_oid(d->crt, oid.constData(), critical);
    return GNUTLS_E_SUCCESS == d->errno;
}

bool CertificateBuilder::setKeyUsage(KeyUsageFlags usages)
{
    uint usage = 0;
    if (usages & UsageEncipherOnly)
        usage |= GNUTLS_KEY_ENCIPHER_ONLY;
    if (usages & UsageCrlSign)
        usage |= GNUTLS_KEY_CRL_SIGN;
    if (usages & UsageKeyCertSign)
        usage |= GNUTLS_KEY_KEY_CERT_SIGN;
    if (usages & UsageKeyAgreement)
        usage |= GNUTLS_KEY_KEY_AGREEMENT;
    if (usages & UsageDataEncipherment)
        usage |= GNUTLS_KEY_DATA_ENCIPHERMENT;
    if (usages & UsageKeyEncipherment)
        usage |= GNUTLS_KEY_KEY_ENCIPHERMENT;
    if (usages & UsageNonRepudiation)
        usage |= GNUTLS_KEY_NON_REPUDIATION;
    if (usages & UsageDigitalSignature)
        usage |= GNUTLS_KEY_DIGITAL_SIGNATURE;
    if (usages & UsageDecipherOnly)
        usage |= GNUTLS_KEY_DECIPHER_ONLY;

    d->errno = gnutls_x509_crt_set_key_usage(d->crt, usage);
    return GNUTLS_E_SUCCESS == d->errno;
}

bool CertificateBuilder::addSubjectKeyIdentifier()
{
    QByteArray ba(128, 0); // Normally 20 bytes (SHA1)
    size_t size = ba.size();

    d->errno = gnutls_x509_crt_get_key_id(d->crt, 0, reinterpret_cast<unsigned char *>(ba.data()), &size);
    if (GNUTLS_E_SUCCESS != d->errno)
        return false;

    d->errno = gnutls_x509_crt_set_subject_key_id (d->crt, ba.constData(), size);
    return GNUTLS_E_SUCCESS == d->errno;
}

QSslCertificate CertificateBuilder::signedCertificate(const QSslKey &qkey)
{
    gnutls_x509_privkey_t key = qsslkey_to_key(qkey, &d->errno);
    if (GNUTLS_E_SUCCESS != d->errno) {
        gnutls_x509_privkey_deinit(key);
        return QSslCertificate();
    };

    gnutls_privkey_t abstractKey;
    d->errno = gnutls_privkey_init(&abstractKey);
    if (GNUTLS_E_SUCCESS != d->errno) {
        gnutls_x509_privkey_deinit(key);
        return QSslCertificate();
    }

    gnutls_privkey_import_x509(abstractKey, key, GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE);

    // TODO: self sign only for now
    d->errno = gnutls_x509_crt_privkey_sign(d->crt, d->crt, abstractKey, GNUTLS_DIG_SHA1, 0);

    gnutls_x509_privkey_deinit(key);

    if (GNUTLS_E_SUCCESS != d->errno)
        return QSslCertificate();

    return crt_to_qsslcert(d->crt, &d->errno);    
}

QSslCertificate CertificateBuilder::signedCertificate(const QSslCertificate &qcacert, const QSslKey &qcakey)
{
    //
    // Extract the CA key
    //
    gnutls_x509_privkey_t key = qsslkey_to_key(qcakey, &d->errno);
    if (GNUTLS_E_SUCCESS != d->errno) {
        gnutls_x509_privkey_deinit(key);
        return QSslCertificate();
    };

    gnutls_privkey_t abstractKey;
    d->errno = gnutls_privkey_init(&abstractKey);
    if (GNUTLS_E_SUCCESS != d->errno) {
        gnutls_x509_privkey_deinit(key);
        return QSslCertificate();
    }

    gnutls_privkey_import_x509(abstractKey, key, GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE);

    //
    // Extract the CA cert
    //
    gnutls_x509_crt_t cacrt = qsslcert_to_crt(qcacert, &d->errno);
    if (GNUTLS_E_SUCCESS != d->errno) {
        gnutls_x509_privkey_deinit(key);
        return QSslCertificate();
    }

    //
    // Sign the cert
    //
    d->errno = gnutls_x509_crt_privkey_sign(d->crt, cacrt, abstractKey, GNUTLS_DIG_SHA1, 0);

    gnutls_x509_crt_deinit(cacrt);
    gnutls_x509_privkey_deinit(key);

    if (GNUTLS_E_SUCCESS != d->errno)
        return QSslCertificate();

    return crt_to_qsslcert(d->crt, &d->errno);
}

QT_END_NAMESPACE_CERTIFICATE
