// -*- c++ -*-

#ifndef CERTIFICATEBUILDER_H
#define CERTIFICATEBUILDER_H

#include <QString>
#include <QFlags>
#include <QtNetwork/QSslCertificate>

#include "certificate_global.h"

class QDateTime;

QT_BEGIN_NAMESPACE_CERTIFICATE

class CertificateRequest;

class Q_CERTIFICATE_EXPORT CertificateBuilder
{
public:
    enum KeyPurpose {
        PurposeWebServer,
        PurposeWebClient,
        PurposeCodeSigning,
        PurposeEmailProtection,
        PurposeTimeStamping,
        PurposeOcspSigning,
        PurposeIpsecIke,
        PurposeAny
    };

    enum KeyUsageFlag {
        UsageEncipherOnly = 0x1,
        UsageCrlSign = 0x2,
        UsageKeyCertSign = 0x4,
        UsageKeyAgreement = 0x8,
        UsageDataEncipherment = 0x10,
        UsageKeyEncipherment = 0x20,
        UsageNonRepudiation = 0x40,
        UsageDigitalSignature = 0x80,
        UsageDecipherOnly = 0x100
    };
    Q_DECLARE_FLAGS(KeyUsageFlags, KeyUsageFlag)

    CertificateBuilder();
    ~CertificateBuilder();

    int error() const;
    QString errorString() const;

    bool setRequest(const CertificateRequest &crq);

    bool setVersion(int version=3);
    bool setSerial(const QByteArray &serial);

    bool setActivationTime(const QDateTime &date);
    bool setExpirationTime(const QDateTime &date);

    // Extensions

    bool copyRequestExtensions(const CertificateRequest &crq);
    bool setBasicConstraints(bool ca=false, int pathLength=-1);

    // Extended usage
    bool addKeyPurpose(KeyPurpose purpose, bool critical=false);
    bool addKeyPurpose(const QByteArray &oid, bool critical=false);

    // Usage
    bool setKeyUsage(KeyUsageFlags usage);

    // Key identifiers
    bool addSubjectKeyIdentifier();
    bool addAuthorityKeyIdentifier(const QSslCertificate &cacert);

    QSslCertificate signedCertificate(const QSslKey &key);
    QSslCertificate signedCertificate(const QSslCertificate &cacert, const QSslKey &cakey);

private:
    struct CertificateBuilderPrivate *d;
};

Q_DECLARE_OPERATORS_FOR_FLAGS(CertificateBuilder::KeyUsageFlags)

QT_END_NAMESPACE_CERTIFICATE

#endif // CERTIFICATEBUILDER_H
