// -*- c++ -*-

#ifndef CERTIFICATE_H
#define CERTIFICATE_H

QT_BEGIN_NAMESPACE_CERTIFICATE

namespace Certificate {
    enum EntryType {
        EntryCountryName,
        EntryOrganizationName,
        EntryOrganizationalUnitName,
        EntryCommonName,
        EntryLocalityName,
        EntryStateOrProvinceName,
        EntryEmail
    };
};

QT_END_NAMESPACE_CERTIFICATE


#endif // CERTIFICATE_H

