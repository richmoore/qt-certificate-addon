// -*- c++ -*-

#ifndef CERTIFICATEREQUESTBUILDER_H
#define CERTIFICATEREQUESTBUILDER_H

#include <QSslKey>
#include <QStringList>

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

    QList<QByteArray> nameEntryAttributes();
    QStringList nameEntryInfo(Certificate::EntryType attribute);
    QStringList nameEntryInfo(const QByteArray &attribute);

#if QT_VERSION >= 0x050000
    bool addSubjectAlternativeNameEntry(QSsl::AlternativeNameEntryType type, const QByteArray &value);
#else
    bool addSubjectAlternativeNameEntry(QSsl::AlternateNameEntryType type, const QByteArray &value);
#endif

    CertificateRequest signedRequest(const QSslKey &key);

private:
    struct CertificateRequestBuilderPrivate *d;
};

QT_END_NAMESPACE_CERTIFICATE

#endif // CERTIFICATEREQUESTBUILDER_H

