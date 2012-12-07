#include <QtTest/QtTest>

#include "certificaterequest.h"

QT_USE_NAMESPACE_CERTIFICATE

class tst_CertificateRequest : public QObject
{
    Q_OBJECT

private slots:
    void checkNull();
    void loadCrq();
    void checkEntries();
};

void tst_CertificateRequest::checkNull()
{
    CertificateRequest csr;
    QVERIFY(csr.isNull());
}

void tst_CertificateRequest::loadCrq()
{
    QFile f("requests/test-ocsp-good-req.pem");
    f.open(QIODevice::ReadOnly);
    CertificateRequest csr(&f);
    f.close();

    QVERIFY(!csr.isNull());
    QVERIFY(csr.version() == 1);

    QFile f2("requests/test-ocsp-good-req.pem");
    f2.open(QIODevice::ReadOnly);
    QByteArray filePem = f2.readAll();
    f2.close();

    QVERIFY(filePem == csr.toPem());
}

void tst_CertificateRequest::checkEntries()
{
    QFile f("requests/test-ocsp-good-req.pem");
    f.open(QIODevice::ReadOnly);
    CertificateRequest csr(&f);
    f.close();

    QStringList commonName;
    commonName << "example.com";
    QVERIFY(commonName ==  csr.nameEntryInfo(Certificate::EntryCommonName));

    QStringList organizationName;
    organizationName << "Some organisation";
    QVERIFY(organizationName ==  csr.nameEntryInfo(Certificate::EntryOrganizationName));

    QStringList countryName;
    countryName << "UK";
    QVERIFY(countryName ==  csr.nameEntryInfo(Certificate::EntryCountryName));

    QStringList email;
    email << "test@example.com";
    QVERIFY(email ==  csr.nameEntryInfo(Certificate::EntryEmail));

    QStringList stateOrProvinceName;
    stateOrProvinceName << "Lancashire";
    QVERIFY(stateOrProvinceName ==  csr.nameEntryInfo(Certificate::EntryStateOrProvinceName));

    QStringList localityName;
    QVERIFY(localityName == csr.nameEntryInfo(Certificate::EntryLocalityName));
}


QTEST_MAIN(tst_CertificateRequest)
#include "tst_certificaterequest.moc"
