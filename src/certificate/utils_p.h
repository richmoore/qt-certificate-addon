// -*- c++ -*-

#ifndef UTILS_P_H
#define UTILS_P_H

#include <gnutls/x509.h>

#include "certificate_global.h"

class QSslKey;

QT_BEGIN_NAMESPACE_CERTIFICATE

void ensure_gnutls_init();

int qsslkey_to_key(const QSslKey &qkey, gnutls_x509_privkey_t key);

QT_END_NAMESPACE_CERTIFICATE

#endif // UTILS_P_H
