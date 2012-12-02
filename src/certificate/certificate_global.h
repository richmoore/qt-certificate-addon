// -*- c++ -*-

#ifndef CERTIFICATE_GLOBAL_H
#define CERTIFICATE_GLOBAL_H

#include "qglobal.h"

#if defined(QT_CERTIFICATE_LIB)
#  define Q_CERTIFICATE_EXPORT Q_DECL_EXPORT
#else
#  define Q_CERTIFICATE_EXPORT Q_DECL_IMPORT
#endif

#if defined(QT_NAMESPACE)
#  define QT_BEGIN_NAMESPACE_CERTIFICATE namespace QT_NAMESPACE { namespace QtAddOn { namespace Certificate {
#  define QT_END_NAMESPACE_CERTIFICATE } } }
#  define QT_USE_NAMESPACE_CERTIFICATE using namespace QT_NAMESPACE::QtAddOn::Certificate;
#  define QT_PREPEND_NAMESPACE_CERTIFICATE(name) ::QT_NAMESPACE::QtAddOn::Certificate::name
#else
#  define QT_BEGIN_NAMESPACE_CERTIFICATE namespace QtAddOn { namespace Certificate {
#  define QT_END_NAMESPACE_CERTIFICATE } }
#  define QT_USE_NAMESPACE_CERTIFICATE using namespace QtAddOn::Certificate;
#  define QT_PREPEND_NAMESPACE_CERTIFICATE(name) ::QtAddOn::Certificate::name
#endif

// a workaround for moc - if there is a header file that doesn't use certificate
// namespace, we still force moc to do "using namespace" but the namespace have to
// be defined, so let's define an empty namespace here
QT_BEGIN_NAMESPACE_CERTIFICATE
QT_END_NAMESPACE_CERTIFICATE

#endif // CERTIFICATE_GLOBAL_H
