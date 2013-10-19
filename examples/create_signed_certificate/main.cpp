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

void save_key(const QString &filename, const QSslKey &key)
{
    QFile k(filename);
    k.open(QIODevice::WriteOnly);
    k.write(key.toPem());
    k.close();
}

void save_request(const QString &filename, CertificateRequest &req)
{
    QFile k(filename);
    k.open(QIODevice::WriteOnly);
    k.write(req.toPem());
    k.close();
}

void save_certificate(const QString &filename, const QSslCertificate &crt)
{
    QFile k(filename);
    k.open(QIODevice::WriteOnly);
    k.write(crt.toPem());
    k.close();
}

int main(int argc, char **argv)
{
    //
    // Create the CA key
    //
    QSslKey cakey = KeyBuilder::generate(QSsl::Rsa, KeyBuilder::StrengthNormal);
    save_key("ca.key", cakey);

    CertificateRequestBuilder careqbuilder;
    careqbuilder.setVersion(1);
    careqbuilder.setKey(cakey);
    careqbuilder.addNameEntry(Certificate::EntryCountryName, "GB");
    careqbuilder.addNameEntry(Certificate::EntryOrganizationName, "Westpoint CA Key");
    careqbuilder.addNameEntry(Certificate::EntryOrganizationName, "Westpoint");

    // Sign the request
    CertificateRequest careq = careqbuilder.signedRequest(cakey);
    save_request("ca.req", careq);

    //
    // Now make a certificate
    //
    CertificateBuilder cabuilder;
    cabuilder.setRequest(careq);

    cabuilder.setVersion(3);
    cabuilder.setSerial("helloworld");
    cabuilder.setActivationTime(QDateTime::currentDateTimeUtc());
    cabuilder.setExpirationTime(QDateTime::currentDateTimeUtc());
    cabuilder.setBasicConstraints(true);
    cabuilder.setKeyUsage(CertificateBuilder::UsageCrlSign|CertificateBuilder::UsageKeyCertSign);
    cabuilder.addSubjectKeyIdentifier();

    QSslCertificate cacert = cabuilder.signedCertificate(cakey);
    save_certificate("ca.crt", cacert);

    //
    // Create the leaf
    //
    QSslKey leafkey = KeyBuilder::generate(QSsl::Rsa, KeyBuilder::StrengthNormal);
    save_key("leaf.key", leafkey);

    CertificateRequestBuilder leafreqbuilder;
    leafreqbuilder.setVersion(1);
    leafreqbuilder.setKey(leafkey);
    leafreqbuilder.addNameEntry(Certificate::EntryCountryName, "GB");
    leafreqbuilder.addNameEntry(Certificate::EntryOrganizationName, "Westpoint");
    leafreqbuilder.addNameEntry(Certificate::EntryCommonName, "www.example.com");

    CertificateRequest leafreq = leafreqbuilder.signedRequest(leafkey);
    save_request("leaf.req", careq);

    CertificateBuilder leafbuilder;
    leafbuilder.setRequest(leafreq);

    leafbuilder.setVersion(3);
    leafbuilder.setSerial("iamaleaf");
    leafbuilder.setActivationTime(QDateTime::currentDateTimeUtc());
    leafbuilder.setExpirationTime(QDateTime::currentDateTimeUtc());
    leafbuilder.setBasicConstraints(false);
    leafbuilder.addKeyPurpose(CertificateBuilder::PurposeWebServer);
    leafbuilder.setKeyUsage(CertificateBuilder::UsageKeyAgreement|CertificateBuilder::UsageKeyEncipherment);
    leafbuilder.addSubjectKeyIdentifier();
    leafbuilder.addAuthorityKeyIdentifier(cacert);

    QSslCertificate leafcert = leafbuilder.signedCertificate(cacert, cakey);
    save_certificate("leaf.crt", leafcert);
}
