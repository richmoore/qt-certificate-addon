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

    QVERIFY( QString("example.com") ==  csr.nameEntryInfo(Certificate::EntryCommonName)[0]);
    QVERIFY( QString("Some organisation") ==  csr.nameEntryInfo(Certificate::EntryOrganizationName)[0]);
    QVERIFY( QString("UK") ==  csr.nameEntryInfo(Certificate::EntryCountryName)[0]);
    QVERIFY( QString("test@example.com") ==  csr.nameEntryInfo(Certificate::EntryEmail)[0]);
    QVERIFY( QString("Lancashire") ==  csr.nameEntryInfo(Certificate::EntryStateOrProvinceName)[0]);
    QVERIFY( QString("Some organisation") ==  csr.nameEntryInfo(Certificate::EntryOrganizationName)[0]);
    QVERIFY( csr.nameEntryInfo(Certificate::EntryLocalityName).length() == 0);
}


QTEST_MAIN(tst_CertificateRequest)
#include "tst_certificaterequest.moc"
