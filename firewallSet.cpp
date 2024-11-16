#include <QCoreApplication>
#include <QDBusInterface>
#include <QDBusConnection>
#include <QDBusReply>
#include <QTimer>
#include <QStandardPaths>
#include <QTextStream>
#include <QDateTime>
#include <QVariantMap>
#include <QNetworkReply>
#include <QCommandLineParser>
#include <QCommandLineOption>
#include <QSystemTrayIcon>
#include <QApplication>
#include <QMessageBox>
#include <string>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <QHostInfo>
#include <QFile>
#include <QProcess>
#include <QString>
#include <QTextStream>
#include <QDateTime>
#include <QDir>
#include <QDebug>

using namespace std;

#define FIREWALL_PATH "/org/fedoraproject/FirewallD1"
#define FIREWALL_INTERFACE "org.fedoraproject.FirewallD1"

class FirewallManager : public QObject {
    Q_OBJECT
public:
    explicit FirewallManager(QDBusConnection &bus, QObject *parent = nullptr) : QObject(parent) {
        firewallInterface = new QDBusInterface(FIREWALL_INTERFACE, FIREWALL_PATH, FIREWALL_INTERFACE, bus, this);
        if (!firewallInterface->isValid()) {
            cerr << "Error: Unable to get firewalld interface." << endl;
            exit(1);
        }
    }

    void executeCommand(const string &command) {
        cout << "executing: " << command << endl;
        int status = system(command.c_str());
        if (status != 0) {
            cerr << "Error: " << command << " failed" << endl;
        }
    }

    void installingQT() {
        executeCommand("sudo apt-get install -y qt5-default");
        sleep(5);
        executeCommand("sudo systemctl status firewalld");
        sleep(5);
        executeCommand("sudo apt install -y openvpn");
        sleep(10);
        executeCommand("sudo systemctl start firewalld");
        sleep(10);
        executeCommand("sudo apt update");
        sleep(10);
        executeCommand("sudo apt upgrade");
    }

    void connectToVpn(){
        QString vpnCommand = "openvpn --config /path/to/vpn-config.ovpn"; // Adjust to your VPN configuration file
        QProcess process;
        process.start(vpnCommand);
        process.waitForFinished();
        if (process.exitcode() == 0) {
            cout << "Connected to VPN successfully." << endl;
        }else{
            cerr << "Error: Unable to connect to VPN." << process.errorString().toStdString() << endl; 
        }

    }

    // Function to log messages to a file
    void logMessage(const QString &message) {
        QString logDirPath = QDir::homePath() + "/FirewallManagerLogs";
        QDir logDir(logDirPath);
    
        if (!logDir.exists()) {
            if (!logDir.mkpath(".")) {
                qCritical() << "Failed to create log directory:" << logDirPath;
                return;
            }
    }

        QString logFilePath = logDir.filePath("firewall_manager.log");
        QFile logFile(logFilePath);

        if (!logFile.open(QIODevice::Append | QIODevice::Text)) {
            qCritical() << "Failed to open log file:" << logFilePath;
            return;
        }

        QTextStream out(&logFile);
        out << QDateTime::currentDateTime().toString(Qt::ISODate) << ": " << message << "\n";
        logFile.close();
    }

// Function to parse a simple configuration file
    QMap<QString, QString> loadConfig(const QString &configFilePath) {
        QMap<QString, QString> configMap;
        QFile configFile(configFilePath);

        if (!configFile.exists()) {
            qWarning() << "Configuration file not found:" << configFilePath;
            return configMap;
        }

        if (!configFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
            qWarning() << "Unable to open configuration file:" << configFilePath;
            return configMap;
        }

        QTextStream in(&configFile);
        while (!in.atEnd()) {
            QString line = in.readLine().trimmed();
            if (line.isEmpty() || line.startsWith("#")) {
                continue; // Skip empty lines or comments
            }

            QStringList keyValue = line.split("=");
            if (keyValue.size() == 2) {
                configMap[keyValue[0].trimmed()] = keyValue[1].trimmed();
            } else {
                qWarning() << "Malformed line in config file:" << line;
            }
        }

        configFile.close();
        return configMap;
    }

    // Function to save a simple configuration file
    bool saveConfig(const QString &configFilePath, const QMap<QString, QString> &configMap) {
        QFile configFile(configFilePath);

        if (!configFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
            qWarning() << "Unable to open configuration file for writing:" << configFilePath;
            return false;
        }

        QTextStream out(&configFile);
        for (auto it = configMap.begin(); it != configMap.end(); ++it) {
            out << it.key() << "=" << it.value() << "\n";
        }

        configFile.close();
        return true;
    }

    // Example usage within this file (optional)
    void testUtilities() {
        QString configPath = QDir::homePath() + "/FirewallManagerConfig/config.txt";

        // Load configuration
        QMap<QString, QString> config = loadConfig(configPath);
        if (config.isEmpty()) {
            qDebug() << "No configuration found, creating a new one.";
            config["vpnConfigPath"] = "/path/to/vpn-config.ovpn";
            config["logLevel"] = "DEBUG";
            saveConfig(configPath, config);
        } else {
            qDebug() << "Loaded configuration:";
            for (auto it = config.begin(); it != config.end(); ++it) {
                qDebug() << it.key() << ":" << it.value();
            }
        }

        // Log a test message
        logMessage("FirewallManager started successfully.");
    }


    void cdFile() {
        QString DesktopPath = QStandardPaths::writableLocation(QStandardPaths::DesktopLocation);
        if (DesktopPath.isEmpty()) {
            cerr << "Error: Unable to get desktop path" << endl;
            return;
        }
        QString logFilePath = DesktopPath + "/firewall_logs.txt";

        // Create the log file
        QFile logFile(logFilePath);
        if (!logFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
            cerr << "Error: Unable to create log file." << endl;
            return;
        }
        QTextStream out(&logFile);
        out << "Firewall logs: " << QDateTime::currentDateTime().toString(Qt::ISODate) << "\n";
        logFile.close();
        cout << "Log file created at: " << logFilePath.toStdString() << endl;
    }

    void blockWebsite(const QString &website) {
        QHostInfo hostInfo = QHostInfo::fromName(website);
        if (hostInfo.error() != QHostInfo::NoError) {
            cerr << "Error: Unable to resolve domain " << website.toStdString() << endl;
            return;
        }

        for (const QHostAddress &address : hostInfo.addresses()) {
            QString ip = address.toString();
            cout << "Blocking website " << website.toStdString() << " (IP: " << ip.toStdString() << ")" << endl;

            QDBusMessage reply = firewallInterface->call("add", ip, "0.0.0.0/0", "any");
            if (reply.type() == QDBusMessage::ReplyMessage) {
                cout << "Blocked: " << ip.toStdString() << endl;
            } else {
                cerr << "Error: Unable to block IP " << ip.toStdString() << endl;
            }
        }
    }

    void addFirewallRule(const QString &sourceIP, const QString &destIP, const QString &port) {
        QDBusMessage reply = firewallInterface->call("add", sourceIP, destIP, port);
        if (reply.type() == QDBusMessage::ReplyMessage) {
            cout << "Firewall rule added: " << sourceIP.toStdString() << " -> " << destIP.toStdString() << ":" << port.toStdString() << endl;
        } else {
            cerr << "Error: Unable to add firewall rule." << endl;
        }
    }

    void removeFirewallRule(const QString &ruleID) {
        QDBusMessage reply = firewallInterface->call("remove", ruleID);
        if (reply.type() == QDBusMessage::ReplyMessage) {
            cout << "Firewall rule removed: " << ruleID.toStdString() << endl;
        } else {
            cerr << "Error: Unable to remove firewall rule." << endl;
        }
    }

    void enableFirewall() {
        QDBusMessage reply = firewallInterface->call("enable");
        if (reply.type() == QDBusMessage::ReplyMessage) {
            cout << "Firewall enabled." << endl;
        } else {
            cerr << "Error: Unable to enable firewall." << endl;
        }
    }

    void disableFirewall() {
        QDBusMessage reply = firewallInterface->call("disable");
        if (reply.type() == QDBusMessage::ReplyMessage) {
            cout << "Firewall disabled." << endl;
        } else {
            cerr << "Error: Unable to disable firewall." << endl;
        }
    }

    void listFirewallRules() {
        QDBusReply<QStringList> reply = firewallInterface->call("listRules");
        if (reply.isValid()) {
            cout << "Current firewall rules:" << endl;
            for (const QString &rule : reply.value()) {
                cout << "- " << rule.toStdString() << endl;
            }
        } else {
            cerr << "Error: Unable to retrieve firewall rules." << endl;
        }
    }

    void getTrafficStats() {
        QDBusReply<QVariantMap> reply = firewallInterface->call("getTrafficStatistics");
        if (reply.isValid()) {
            QVariantMap stats = reply.value();
            cout << "Traffic statistics:" << endl;
            cout << "Packets: " << stats["packets"].toInt() << endl;
            cout << "Bytes: " << stats["bytes"].toInt() << endl;
        } else {
            cerr << "Error: Unable to retrieve traffic statistics." << endl;
        }
    }

    void scheduleFirewallChange(const QDateTime &scheduledTime, const QString &action) {
        int delay = QDateTime::currentDateTime().msecsTo(scheduledTime);
        if (delay <= 0) {
            cerr << "Error: Scheduled time is invalid or in the past." << endl;
            return;
        }

        QTimer *timer = new QTimer(this);
        connect(timer, &QTimer::timeout, [this, action, timer] {
            if (action == "enable") {
                this->enableFirewall();
            } else if (action == "disable") {
                this->disableFirewall();
            } else {
                cerr << "Error: Unknown action for scheduling." << endl;
            }
            timer->deleteLater();
        });
        timer->start(delay);
        cout << "Scheduled action (" << action.toStdString() << ") at "
             << scheduledTime.toString(Qt::ISODate).toStdString() << endl;
    }

    void addAdvancedFirewallRule(const QString &sourceIP, const QString &destIP, const QString &port, const QString &protocol) {
        QDBusMessage reply = firewallInterface->call("addAdvancedRule", sourceIP, destIP, port, protocol);
        if (reply.type() == QDBusMessage::ReplyMessage) {
            cout << "Advanced firewall rule added: " << sourceIP.toStdString() << " -> " << destIP.toStdString() << ":" << port.toStdString() << " Protocol: " << protocol.toStdString() << endl;
        } else {
            cerr << "Error: Unable to add advanced firewall rule." << endl;
        }
    }

    void blockIPAddress(const QString &ipAddress) {
        cout << "Blocking IP address: " << ipAddress.toStdString() << endl;

        QDBusMessage reply = firewallInterface->call("blockIP", ipAddress);
        if (reply.type() == QDBusMessage::ReplyMessage) {
            cout << "IP blocked: " << ipAddress.toStdString() << endl;
        } else {
            cerr << "Error: Unable to block IP address." << endl;
        }
    }

    void unblockIPAddress(const QString &ipAddress) {
        cout << "Unblocking IP address: " << ipAddress.toStdString() << endl;

        QDBusMessage reply = firewallInterface->call("unblockIP", ipAddress);
        if (reply.type() == QDBusMessage::ReplyMessage) {
            cout << "IP unblocked: " << ipAddress.toStdString() << endl;
        } else {
            cerr << "Error: Unable to unblock IP address." << endl;
        }
    }

    void FirewallManager::sendNotification(const QString &message) {
    QProcess process;
    process.start("notify-send", QStringList() << "Firewall Alert" << message);
    process.waitForFinished();
    }
    void ruleViolationDetected(const QString &rule, const QString &violationDetail) {
    QString message = "Rule violation detected: " + rule + " - " + violationDetail;
    sendNotification(message);  // Send a desktop notification
    }

private:
    QDBusInterface *firewallInterface;
};

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);
    QCommandLineParser parser;
    parser.setApplicationDescription("Manage Firewall Rules using D-Bus");
    parser.addHelpOption();
    parser.addVersionOption();

    QCommandLineOption blockWebsiteOption("block-website", "Block a specific website <domain>");
    parser.addOption(blockWebsiteOption);

    QDBusConnection bus = QDBusConnection::systemBus();
    if (!bus.isConnected()) {
        cerr << "Error: Unable to connect to D-Bus system bus." << endl;
        return 1;
    }

    FirewallManager firewallManager(bus);

    if (parser.isSet(blockWebsiteOption)) {
        if (parser.positionalArguments().size() < 1) {
            cerr << "Error: Missing domain name for blocking website." << endl;
            return 1;
        }
        QString website = parser.positionalArguments().at(0);
        firewallManager.blockWebsite(website);
    }
    firewallManager.ruleViolationDetected("Blocked Port", "Unauthorized access attempt detected on port 8080");
    

    return app.exec();
}

#include "main.moc"

