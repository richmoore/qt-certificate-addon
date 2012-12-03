#include <QtTest/QtTest>

#include "certificaterequest.h"

QT_USE_NAMESPACE_CERTIFICATE

class tst_CertificateRequest : public QObject
{
    Q_OBJECT

private slots:
    void checkNull();
    void loadCrq();
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

QTEST_MAIN(tst_CertificateRequest)
#include "tst_certificaterequest.moc"
