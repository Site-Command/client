#pragma once

#include <QVariant>

#include <qt5keychain/keychain.h>

namespace OCC {
class Account;
class CredentialJob;

class CredentialManager : public QObject
{
    Q_OBJECT
public:
    // global credentials
    CredentialManager(QObject *parent);
    // account related credentials
    explicit CredentialManager(Account *acc);
    CredentialJob *getCredentials(const QString &key);
    void setCredentials(const QString &key, const QVariant &data);
    void deleteCredentials(const QString &key) {
        setCredentials(key, {});
    }

Q_SIGNALS:
    void error(const QString &key, QKeychain::Error error, const QString &errorString);
private:
    const Account *const _account = nullptr;
};

class CredentialJob : public QObject{
    Q_OBJECT
public:

    void start();
    QString key() const;

    QKeychain::Error error() const;

    const QVariant &data() const;

    QString errorString() const;

Q_SIGNALS:
    void finished();
private:
    CredentialJob(const QString &scope, const QString &key, QObject *parent);
    QString _scope;
    QString _key;
    QVariant _data;
    QKeychain::Error _error = QKeychain::NoError;
    QString _errorString;

    friend class CredentialManager;
};


}
