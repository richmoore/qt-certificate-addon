// -*- c++ -*-

#ifndef CERTIFICATEREQUESTBUILDER_P_H
#define CERTIFICATEREQUESTBUILDER_P_H

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "certificaterequestbuilder.h"

QT_BEGIN_NAMESPACE_CERTIFICATE

struct CertificateRequestBuilderPrivate
{
    int errno;
    gnutls_x509_crq_t crq;
};

QT_END_NAMESPACE_CERTIFICATE

#endif // CERTIFICATEREQUESTBUILDER_P_H
