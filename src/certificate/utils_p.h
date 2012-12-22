// -*- c++ -*-

#ifndef UTILS_P_H
#define UTILS_P_H

#include <gnutls/x509.h>

#include <QtNetwork/QSsl>
#include <QtCore/QByteArray>

#include "certificate_global.h"
#include "certificate.h"

class QSslKey;
class QSslCertificate;

QT_BEGIN_NAMESPACE_CERTIFICATE

void ensure_gnutls_init();

QByteArray entrytype_to_oid(Certificate::EntryType type);

gnutls_x509_privkey_t qsslkey_to_key(const QSslKey &qkey, int *errno);
gnutls_x509_crt_t qsslcert_to_crt(const QSslCertificate &qcert, int *errno);

QSslCertificate crt_to_qsslcert(gnutls_x509_crt_t crt, int *errno);
QSslKey key_to_qsslkey(gnutls_x509_privkey_t key, QSsl::KeyAlgorithm algo, int *errno);

#if QT_VERSION >= 0x050000
gnutls_x509_subject_alt_name_t qssl_altnameentrytype_to_altname(QSsl::AlternativeNameEntryType qtype);
#else
gnutls_x509_subject_alt_name_t qssl_altnameentrytype_to_altname(QSsl::AlternateNameEntryType qtype);
#endif

QT_END_NAMESPACE_CERTIFICATE

#endif // UTILS_P_H
