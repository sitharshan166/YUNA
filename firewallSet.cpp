#include <QCoreApplication>
#include <QDBusInterface>
#include <QDBusConnection>
#include <QDBusReply>
#include <iostream>

#define NM_PATH "/org/freedesktop/NetworkManager"
#define NM_INTERFACE "org.freedesktop.NetworkManager"
#define FIREWALL_PATH "/org/fedoraproject/FirewallD1"
#define FIREWALL_INTERFACE "org.fedoraproject.FirewallD1"

// Class to manage the firewall
class FirewallManager : public QObject {
    Q_OBJECT
public:
    explicit FirewallManager(QDBusConnection &bus, QObject *parent = nullptr) : QObject(parent) {
        // Get firewalld interface
        firewallInterface = new QDBusInterface(FIREWALL_INTERFACE, FIREWALL_PATH, FIREWALL_INTERFACE, bus, this);
        if (!firewallInterface->isValid()) {
            std::cerr << "Error: Unable to get firewalld interface." << std::endl;
            exit(1);
        }
    }

    // Function to add a firewall rule
    void addFirewallRule(const QString &sourceIP, const QString &destIP, const QString &port) {
        QDBusMessage reply = firewallInterface->call("AddRule", sourceIP, destIP, port);
        if (reply.type() == QDBusMessage::ReplyMessage) {
            std::cout << "Firewall rule added: " << sourceIP.toStdString() << " -> " << destIP.toStdString() << ":" << port.toStdString() << std::endl;
        } else {
            std::cerr << "Error: Unable to add firewall rule." << std::endl;
        }
    }

    // Function to remove a firewall rule
    void removeFirewallRule(const QString &ruleID) {
        QDBusMessage reply = firewallInterface->call("RemoveRule", ruleID);
        if (reply.type() == QDBusMessage::ReplyMessage) {
            std::cout << "Firewall rule removed: " << ruleID.toStdString() << std::endl;
        } else {
            std::cerr << "Error: Unable to remove firewall rule." << std::endl;
        }
    }

    // Function to enable the firewall
    void enableFirewall() {
        QDBusMessage reply = firewallInterface->call("Enable");
        if (reply.type() == QDBusMessage::ReplyMessage) {
            std::cout << "Firewall enabled." << std::endl;
        } else {
            std::cerr << "Error: Unable to enable firewall." << std::endl;
        }
    }

    // Function to disable the firewall
    void disableFirewall() {
        QDBusMessage reply = firewallInterface->call("Disable");
        if (reply.type() == QDBusMessage::ReplyMessage) {
            std::cout << "Firewall disabled." << std::endl;
        } else {
            std::cerr << "Error: Unable to disable firewall." << std::endl;
        }
    }

    // Function to list firewall rules
    void listFirewallRules() {
        QDBusReply<QStringList> reply = firewallInterface->call("ListRules");
        if (reply.isValid()) {
            std::cout << "Current firewall rules:" << std::endl;
            for (const QString &rule : reply.value()) {
                std::cout << "- " << rule.toStdString() << std::endl;
            }
        } else {
            std::cerr << "Error: Unable to retrieve firewall rules." << std::endl;
        }
    }

private:
    QDBusInterface *firewallInterface;
};

// Main application
int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);

    // Connect to system D-Bus
    QDBusConnection bus = QDBusConnection::systemBus();
    if (!bus.isConnected()) {
        std::cerr << "Error: Unable to connect to D-Bus system bus." << std::endl;
        return 1;
    }

    FirewallManager firewallManager(bus);

    if (argc < 2) {
        std::cerr << "Usage:\n";
        std::cerr << argv[0] << " add <sourceIP> <destIP> <port>\n";
        std::cerr << argv[0] << " remove <ruleID>\n";
        std::cerr << argv[0] << " enable\n";
        std::cerr << argv[0] << " disable\n";
        std::cerr << argv[0] << " list\n";
        return 1;
    }

    QString command = argv[1];
    if (command == "add") {
        if (argc < 5) {
            std::cerr << "Error: Missing parameters for adding rule. Provide <sourceIP> <destIP> <port>.\n";
            return 1;
        }
        QString sourceIP = argv[2];
        QString destIP = argv[3];
        QString port = argv[4];
        firewallManager.addFirewallRule(sourceIP, destIP, port);
    } else if (command == "remove") {
        if (argc < 3) {
            std::cerr << "Error: Missing rule ID for removal.\n";
            return 1;
        }
        QString ruleID = argv[2];
        firewallManager.removeFirewallRule(ruleID);
    } else if (command == "enable") {
        firewallManager.enableFirewall();
    } else if (command == "disable") {
        firewallManager.disableFirewall();
    } else if (command == "list") {
        firewallManager.listFirewallRules();
    } else {
        std::cerr << "Error: Unknown command.\n";
        std::cerr << "Usage:\n";
        std::cerr << argv[0] << " add <sourceIP> <destIP> <port>\n";
        std::cerr << argv[0] << " remove <ruleID>\n";
        std::cerr << argv[0] << " enable\n";
        std::cerr << argv[0] << " disable\n";
        std::cerr << argv[0] << " list\n";
        return 1;
    }

    return 0;
}

#include "main.moc"
