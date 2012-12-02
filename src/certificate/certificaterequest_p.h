// -*- c++ -*-

#ifndef CERTIFICATEREQUEST_P_H
#define CERTIFICATEREQUEST_P_H

#include "certificaterequest.h"

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

QT_BEGIN_NAMESPACE_CERTIFICATE

class CertificateRequestPrivate : public QSharedData
{
public:
    CertificateRequestPrivate();
    ~CertificateRequestPrivate();

    bool null;
    int errno;
    gnutls_x509_crq_t crq;
};

QT_END_NAMESPACE_CERTIFICATE

#endif // CERTIFICATEREQUEST_P_H
