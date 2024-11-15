#include <QCoreApplication>
#include <QDBusInterface>
#include <QDBusConnection>
#include <QDBusReply>
#include <QTimer>
#include <QDateTime>
#include <QVariantMap>
#include <QNeteworkReply>
#include <QCommandLineParser>
#include <QCommandLineOption>
#include <string>
#include <cstdlib>
#include <iostream>

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

    void executeCommand(const string& command){
        cout<<"executing: "<<command<<endl;
        int status = system(command.c_str());
        if(status!=0){
        cerr<<"Error: "<<command<<" failed"<<endl;
        }
    }

    void installingQT(){
        executeCommand("sudo apt-get install -y qt5-default");
        sleep (10);
        executeCommand("sudo apt update");
        sleep (10);
        executeCommand("sudo apt upgrade");
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
        // Correcting typo in QVariantMap
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
            cerr << "Error: Scheduled time is in the past." << endl;
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
            timer->deleteLater(); // Clean up the timer after it has fired
        });
        timer->start(delay);  // Start the timer to fire after the calculated delay
        cout << "Scheduled action (" << action.toStdString() << ") at "
             << scheduledTime.toString().toStdString() << endl;
    }

private:
    QDBusInterface *firewallInterface;
};

// Main application
int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);

    // Create QCommandLineParser
    QCommandLineParser parser;
    parser.setApplicationDescription("Manage Firewall Rules using D-Bus");
    parser.addHelpOption();
    parser.addVersionOption();

    // Define options
    QCommandLineOption addOption("add", "Add a firewall rule <sourceIP> <destIP> <port>");
    QCommandLineOption removeOption("remove", "Remove a firewall rule <ruleID>");
    QCommandLineOption enableOption("enable", "Enable the firewall");
    QCommandLineOption disableOption("disable", "Disable the firewall");
    QCommandLineOption listOption("list", "List current firewall rules");
    QCommandLineOption scheduleOption("schedule", "Schedule an action at a specific time <action> <time>");

    // Add options to parser
    parser.addOption(addOption);
    parser.addOption(removeOption);
    parser.addOption(enableOption);
    parser.addOption(disableOption);
    parser.addOption(listOption);
    parser.addOption(scheduleOption);

    // Add positional arguments for 'add' command
    parser.addPositionalArgument("sourceIP", "Source IP for the rule");
    parser.addPositionalArgument("destIP", "Destination IP for the rule");
    parser.addPositionalArgument("port", "Port for the rule");

    // Parse the arguments
    parser.process(app);

    // Connect to system D-Bus
    QDBusConnection bus = QDBusConnection::systemBus();
    if (!bus.isConnected()) {
        cerr << "Error: Unable to connect to D-Bus system bus." << endl;
        return 1;
    }

    FirewallManager firewallManager(bus);

    // Handle the commands based on the options
    if (parser.isSet(addOption)) {
        if (parser.positionalArguments().size() != 3) {
            cerr << "Error: Missing parameters for adding rule. Provide <sourceIP> <destIP> <port>." << endl;
            return 1;
        }
        QString sourceIP = parser.positionalArguments().at(0);
        QString destIP = parser.positionalArguments().at(1);
        QString port = parser.positionalArguments().at(2);
        firewallManager.addFirewallRule(sourceIP, destIP, port);
    } else if (parser.isSet(removeOption)) {
        if (parser.positionalArguments().size() != 1) {
            cerr << "Error: Missing rule ID for removal." << endl;
            return 1;
        }
        QString ruleID = parser.positionalArguments().at(0);
        firewallManager.removeFirewallRule(ruleID);
    } else if (parser.isSet(enableOption)) {
        firewallManager.enableFirewall();
    } else if (parser.isSet(disableOption)) {
        firewallManager.disableFirewall();
    } else if (parser.isSet(listOption)) {
        firewallManager.listFirewallRules();
    } else if (parser.isSet(scheduleOption)) {
        if (parser.positionalArguments().size() != 2) {
            cerr << "Error: Invalid arguments for schedule. Provide <action> <time>" << endl;
            return 1;
        }
        QString action = parser.positionalArguments().at(0);
        QString timeString = parser.positionalArguments().at(1);
        QDateTime scheduledTime = QDateTime::fromString(timeString, Qt::ISODate);

        if (!scheduledTime.isValid()) {
            cerr << "Error: Invalid time format. Please use ISO 8601 format (e.g., 2024-11-15T10:00:00)." << endl;
            return 1;
        }

        firewallManager.scheduleFirewallChange(scheduledTime, action);
    }

    return 0;
}

#include "main.moc"
