// -*- c++ -*-

#ifndef CERTIFICATEREQUEST_H
#define CERTIFICATEREQUEST_H

#include <QtNetwork/QSsl>
#include <QtCore/qshareddata.h>

#include "certificate_global.h"

class QIODevice;

QT_BEGIN_NAMESPACE_CERTIFICATE

class CertificateRequestPrivate;
class CertificateRequestBuilder;

class Q_CERTIFICATE_EXPORT CertificateRequest
{
public:
    CertificateRequest();
    CertificateRequest(const CertificateRequest &other);
    CertificateRequest(QIODevice *io, QSsl::EncodingFormat format=QSsl::Pem);
    ~CertificateRequest();

    CertificateRequest &operator=(const CertificateRequest &other);

    void swap(CertificateRequest &other) { qSwap(d, other.d); }

    bool isNull() const;

    int error() const;
    QString errorString() const;

    // TODO: Include accessors for the fields
    int version() const;

    QByteArray toPem();
    QByteArray toDer();

private:
    friend class CertificateRequestPrivate;
    friend class CertificateRequestBuilder;
    friend class CertificateBuilder;
    QSharedDataPointer<CertificateRequestPrivate> d;
};

QT_END_NAMESPACE_CERTIFICATE

#endif // CERTIFICATEREQUEST_H


