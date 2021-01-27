#include "credentialmanager.h"

#include "account.h"
#include "theme.h"

#include "common/asserts.h"

#include <QJsonParseError>
#include <QJsonObject>
#include <QLoggingCategory>

using namespace OCC;

Q_LOGGING_CATEGORY(lcCredentaislManager, "sync.credentials.manager", QtDebugMsg)

namespace {
QString credentialKeyC() {
    return QStringLiteral("%1_credentials").arg(Theme::instance()->appName());
}

QString accoutnKey(const Account *acc){
    OC_ASSERT(!acc->url().isEmpty());
    return QStringLiteral("%1:%2:%3").arg(credentialKeyC(),
        acc->url().host(),
        acc->uuid().toString(QUuid::WithoutBraces));
}
}

CredentialManager::CredentialManager(Account *acc)
    : QObject(acc)
    , _account(acc)
{

}

CredentialManager::CredentialManager(QObject *parent)
: QObject(parent)
{

}

CredentialJob *CredentialManager::getCredentials(const QString &key)
{
    auto out =  new CredentialJob(_account ? accoutnKey(_account) : credentialKeyC(), key, this);
    connect(out, &CredentialJob::finished, this, [out, this]{
        if (out->error() != QKeychain::NoError) {
            Q_EMIT error(out->key(), out->error(), out->errorString());
        }
    });
    return out;
}

void CredentialManager::setCredentials(const QString &key, const QVariant &data)
{
    const auto scope = _account ? accoutnKey(_account) : credentialKeyC();

    // read and update the current content
    auto keychainJob = new QKeychain::ReadPasswordJob(Theme::instance()->appName());
    keychainJob->setKey(scope);
    connect(keychainJob, &QKeychain::ReadPasswordJob::finished, this, [this, scope, key, data, keychainJob] {
        qCDebug(lcCredentaislManager) << keychainJob->error();
        QJsonObject obj;
        if (keychainJob->error() == QKeychain::NoError) {
            QJsonParseError error;
            obj = QJsonDocument::fromJson(keychainJob->binaryData(), &error).object();
            if (error.error != QJsonParseError::NoError) {
                Q_EMIT this->error(key, QKeychain::OtherError, error.errorString());
                return;
            }
        } else if(keychainJob->error() != QKeychain::EntryNotFound) {
            Q_EMIT error(key, keychainJob->error(), keychainJob->errorString());
            return;
        }
        auto writeJob = new QKeychain::WritePasswordJob(Theme::instance()->appName());
        writeJob->setKey(scope);
        connect(writeJob, &QKeychain::WritePasswordJob::finished, this, [writeJob] {
            if (writeJob->error() != QKeychain::NoError) {
                qCWarning(lcCredentaislManager) << "Failed to save credentials" << writeJob->errorString();
            }
        });
        if (!data.isNull()) {
            obj.insert(key, QJsonValue::fromVariant(data));
        } else {
            obj.remove(key);
        }
        writeJob->setBinaryData(QJsonDocument(obj).toJson());
        writeJob->start();
    });
    keychainJob->start();
}

CredentialJob::CredentialJob(const QString &scope, const QString &key, QObject *parent)
: QObject(parent)
    , _scope(scope)
    , _key(key)
{
    connect(this, &CredentialJob::finished, this, &CredentialJob::deleteLater);
}

QString CredentialJob::errorString() const
{
    return _errorString;
}

const QVariant &CredentialJob::data() const
{
    return _data;
}

QKeychain::Error CredentialJob::error() const
{
    return _error;
}

void CredentialJob::start()
{
    auto keychainJob = new QKeychain::ReadPasswordJob(Theme::instance()->appName());
    keychainJob->setKey(_scope);
    connect(keychainJob, &QKeychain::ReadPasswordJob::finished, this, [this, keychainJob] {
        if (keychainJob->error() == QKeychain::NoError) {
            QJsonParseError error;
            const auto doc = QJsonDocument::fromJson(keychainJob->binaryData(), &error);
            if (error.error == QJsonParseError::NoError) {
                _data = doc.object().toVariantMap().value(_key);
            } else {
                _error = QKeychain::OtherError;
                _errorString = tr("Failed to parse credentials: %1").arg(error.errorString());
            }
        } else if (keychainJob->error() == QKeychain::EntryNotFound) {
            qCDebug(lcCredentaislManager) << "Failed to read client id" << keychainJob->errorString();
        } else {
            qCWarning(lcCredentaislManager) << "Failed to read client id" << keychainJob->errorString();
            _error = keychainJob->error();
            _errorString = keychainJob->errorString();
        }
        Q_EMIT finished();
    });
    keychainJob->start();
}

QString CredentialJob::key() const
{
    return _key;
}

