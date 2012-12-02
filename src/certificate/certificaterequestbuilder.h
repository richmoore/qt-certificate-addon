// -*- c++ -*-

#ifndef CERTIFICATEREQUESTBUILDER_H
#define CERTIFICATEREQUESTBUILDER_H

#include <QSslKey>

#include "certificaterequest.h"

#include "certificate_global.h"

class QIODevice;
class QByteArray;

QT_BEGIN_NAMESPACE_CERTIFICATE

class Q_CERTIFICATE_EXPORT CertificateRequestBuilder
{
public:
    enum EntryType {
        EntryCountryName,
        EntryOrganizationName,
        EntryOrganizationalUnitName,
        EntryCommonName,
        EntryLocalityName,
        EntryStateOrProvinceName,
        EntryEmail
    };

    CertificateRequestBuilder();
    ~CertificateRequestBuilder();

    int error() const;
    QString errorString() const;

    bool setVersion(int version);
    int version() const;

    bool setKey(const QSslKey &key);

    bool addNameEntry(EntryType type, const QByteArray &value);
    bool addNameEntry(const QByteArray &oid, const QByteArray &value, bool raw=false);

    CertificateRequest signedRequest(const QSslKey &key);

private:
    struct CertificateRequestBuilderPrivate *d;
};

QT_END_NAMESPACE_CERTIFICATE

#endif // CERTIFICATEREQUESTBUILDER_H

