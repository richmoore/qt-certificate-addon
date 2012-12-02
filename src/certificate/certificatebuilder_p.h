// -*- c++ -*-

#ifndef CERTIFICATEBUILDER_P_H
#define CERTIFICATEBUILDER_P_H

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "certificatebuilder.h"

QT_BEGIN_NAMESPACE_CERTIFICATE

struct CertificateBuilderPrivate
{
    int errno;
    gnutls_x509_crt_t crt;
};

QT_END_NAMESPACE_CERTIFICATE

#endif // CERTIFICATEBUILDER_P_H

