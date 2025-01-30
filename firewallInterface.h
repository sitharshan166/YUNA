#pragma once

#include <QObject>
#include <QString>
#include <QStringList>
#include <QDBusInterface>

class firewallInterface : public QObject
{
    Q_OBJECT

public:
    explicit firewallInterface(QObject *parent = nullptr);
    ~firewallInterface();

    void addRule(const QString &rule);
    void removeRule(const QString &rule);
    QStringList listRules() const;
    bool isRuleActive(const QString &rule) const;

signals:
    void ruleAdded(const QString &rule);
    void ruleRemoved(const QString &rule);

private:
    QDBusInterface *m_dbusInterface;
};