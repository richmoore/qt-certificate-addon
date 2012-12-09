// -*- c++ -*-

#ifndef CERTIFICATEREQUESTBUILDER_H
#define CERTIFICATEREQUESTBUILDER_H

#include <QSslKey>

#include "certificaterequest.h"
#include "certificate.h"

#include "certificate_global.h"

class QIODevice;
class QByteArray;

QT_BEGIN_NAMESPACE_CERTIFICATE

class Q_CERTIFICATE_EXPORT CertificateRequestBuilder
{
public:
    CertificateRequestBuilder();
    ~CertificateRequestBuilder();

    int error() const;
    QString errorString() const;

    bool setVersion(int version);
    int version() const;

    bool setKey(const QSslKey &key);

    bool addNameEntry(Certificate::EntryType type, const QByteArray &value);
    bool addNameEntry(const QByteArray &oid, const QByteArray &value, bool raw=false);

    bool addSubjectAlternativeNameEntry(QSsl::AlternateNameEntryType type, const QByteArray &value);

    CertificateRequest signedRequest(const QSslKey &key);

private:
    struct CertificateRequestBuilderPrivate *d;
};

QT_END_NAMESPACE_CERTIFICATE

#endif // CERTIFICATEREQUESTBUILDER_H

