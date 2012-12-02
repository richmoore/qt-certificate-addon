// -*- c++ -*-

#ifndef UTILS_P_H
#define UTILS_P_H

#include <gnutls/x509.h>

#include <QtNetwork/QSsl>

#include "certificate_global.h"

class QSslKey;
class QSslCertificate;

QT_BEGIN_NAMESPACE_CERTIFICATE

void ensure_gnutls_init();

gnutls_x509_privkey_t qsslkey_to_key(const QSslKey &qkey, int *errno);
gnutls_x509_crt_t qsslcert_to_crt(const QSslCertificate &qcert, int *errno);

QSslCertificate crt_to_qsslcert(gnutls_x509_crt_t crt, int *errno);
QSslKey key_to_qsslkey(gnutls_x509_privkey_t key, QSsl::KeyAlgorithm algo, int *errno);

QT_END_NAMESPACE_CERTIFICATE

#endif // UTILS_P_H
