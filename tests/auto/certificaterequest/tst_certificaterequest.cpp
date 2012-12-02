#include <QtTest/QtTest>

#include "certificaterequest.h"

QT_USE_NAMESPACE_CERTIFICATE

class tst_CertificateRequest : public QObject
{
    Q_OBJECT

private slots:
    void checkNull();
};

void tst_CertificateRequest::checkNull()
{
    CertificateRequest csr;
    QVERIFY(csr.isNull());
}

QTEST_MAIN(tst_CertificateRequest)
#include "tst_certificaterequest.moc"
