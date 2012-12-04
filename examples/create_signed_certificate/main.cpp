#include <QByteArray>
#include <QFile>
#include <QDateTime>
#include <QSslKey>
#include <QSslCertificate>

#include "keybuilder.h"
#include "certificaterequestbuilder.h"
#include "certificaterequest.h"
#include "certificatebuilder.h"
#include "certificate.h"

QT_USE_NAMESPACE_CERTIFICATE

int main(int argc, char **argv)
{
    //
    // Create the CA key
    //

    QSslKey cakey = KeyBuilder::generate( QSsl::Rsa, KeyBuilder::StrengthNormal );

    QFile k("ca.key");
    k.open(QIODevice::WriteOnly);
    k.write(cakey.toPem());
    k.close();

    CertificateRequestBuilder careqbuilder;
    careqbuilder.setVersion(1);
    careqbuilder.setKey(cakey);
    careqbuilder.addNameEntry(Certificate::EntryCountryName, "GB");
    careqbuilder.addNameEntry(Certificate::EntryOrganizationName, "Westpoint CA Key");
    careqbuilder.addNameEntry(Certificate::EntryOrganizationName, "West");
    careqbuilder.addNameEntry(Certificate::EntryCommonName, "www.example.com");

    // Sign the request
    CertificateRequest careq = careqbuilder.signedRequest(cakey);

    //
    // Export the results
    //
    QFile f("ca.req");
    f.open(QIODevice::WriteOnly);
    f.write(careq.toPem());
    f.close();

    //
    // Now make a certificate
    //
    CertificateBuilder builder;
    builder.setRequest(careq);

    builder.setVersion(3);
    builder.setSerial("helloworld");
    builder.setActivationTime(QDateTime::currentDateTimeUtc());
    builder.setExpirationTime(QDateTime::currentDateTimeUtc());
    builder.setBasicConstraints(true);
    builder.setKeyUsage(CertificateBuilder::UsageCrlSign|CertificateBuilder::UsageKeyCertSign);
    builder.addSubjectKeyIdentifier();

    QSslCertificate cacert = builder.signedCertificate(cakey);

    QFile c("ca.crt");
    c.open(QIODevice::WriteOnly);
    c.write(cacert.toPem());
    c.close();

    //
    // Create the leaf
    //
    builder.setSerial("XXXXXXXXXXXXXXXXXXXXXXX");

    QSslCertificate leafcert = builder.signedCertificate(cacert, cakey);

    QFile d("leaf.crt");
    d.open(QIODevice::WriteOnly);
    d.write(leafcert.toPem());
    d.close();
}
