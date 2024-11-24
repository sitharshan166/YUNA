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
#include <vector>
#include <cmath>
#include <ctime>
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
#include <QHostAddress>

using namespace std;

#define FIREWALL_PATH "/org/fedoraproject/FirewallD1"
#define FIREWALL_INTERFACE "org.fedoraproject.FirewallD1"

struct NetworkFeatures {
    double packetRate;
    double packetSize;
    double connectionDuration;
    double portNumber;
};


// Data structure to store connection state
struct ConnectionState {
    QString state;      // State of the connection (NEW, ESTABLISHED, etc.)
    QString sourceIP;
    QString destIP;
    QString sourcePort;
    QString destPort;
};

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
     void checkInternetConnectivity() {
        QNetworkRequest request(QUrl("http://www.google.com"));
        QNetworkReply *reply = networkManager->get(request);

        connect(reply, &QNetworkReply::finished, this, [reply, this]() {
            if (reply->error() == QNetworkReply::NoError) {
                logInfo("Internet is available.");
                // You can emit a signal or call another function here if needed
            } else {
                logError("Internet is not available: " + reply->errorString());
            }
            reply->deleteLater();
        });
    }

    private:
    // Add these as private members
    NeuralNetwork* neuralNetwork;
    vector<vector<double>> trainingData;
    vector<vector<double>> trainingLabels;
    public:
    void initializeNeuralNetwork() {
        // Initialize with 4 inputs (features), 6 hidden neurons, 1 output (threat score)
        neuralNetwork = new NeuralNetwork(4, 6, 1);
        
        // Initialize random seed
        srand(time(0));
    }

    NetworkFeatures extractFeatures(const ConnectionState& connection) {
        NetworkFeatures features;
        
        // Convert port to normalized value
        features.portNumber = connection.destPort.toDouble() / 65535.0;
        
        // Calculate packet rate (example calculation)
        QDateTime now = QDateTime::currentDateTime();
        int timeDiff = connection.lastUpdate.secsTo(now);
        features.packetRate = connection.packetCount / (timeDiff > 0 ? timeDiff : 1);
        
        // Normalize packet size
        features.packetSize = connection.totalBytes / (1024.0 * 1024.0); // Normalize to MB
        
        // Calculate connection duration in hours and normalize
        features.connectionDuration = timeDiff / 3600.0;
        
        return features;
    }

    vector<double> convertToVector(const NetworkFeatures& features) {
        vector<double> vec;
        vec.push_back(features.packetRate);
        vec.push_back(features.packetSize);
        vec.push_back(features.connectionDuration);
        vec.push_back(features.portNumber);
        return vec;
    }

        // Log an error message
    void logError(const QString &message) {
        Logger::log("ERROR: " + message);
    }

    // Log a warning message
    void logWarning(const QString &message) {
        Logger::log("WARNING: " + message);
    }

    // Log an info message
    void logInfo(const QString &message) {
        Logger::log("INFO: " + message);
    }

    void addNatRule(const QString &sourceIP, const QString &destIP, const QString &port) {
        // Create a new nat rule
        QDBusMessage reply  = firewallInterface->call("AddNatRule", sourceIP, destIP, port);
        if (reply.type() == QDBusMessage::replyMessage) {
            cout << "Nat rule added successfully." << SourceIP.tostdString() << "->"<<destIP.tostdString()<< ":" << port.toStdString() << endl;
        }else{
            cerr << "ERROR: Unable to add NAT rule." << endl;
        }
    }

    void removeNatRule(const QString &ruleID) {
    QDBusMessage reply = firewallInterface->call("removeNatRule", ruleID);
    if (reply.type() == QDBusMessage::ReplyMessage) {
        cout << "NAT rule removed: " << ruleID.toStdString() << endl;
    } else {
        cerr << "Error: Unable to remove NAT rule." << endl;
        }       
    }   
    bool panicModeEnabled = false;

    void togglePanicMode(){
        if(panicModeEnabled){
            panicModeEnabled = false;
            unblockAllTrafic();
            logInfo("Panic mode disabled.");
        }else{
            panicModeEnabled = true;
            blockAllTraffic();
            logInfo("Panic mode enabled.");
        }
    }

    void blockAllTraffic(){
        // Block all incoming and outgoing traffic
        addFirewallRule("block","in","all","all","all");
        addFirewallRule("block","out","all","all","all");
    }

    void unblockAllTraffic()
    {
    // Remove rules to unblock all incoming traffic
    removeFirewallRule("block", "in", "all", "all", "all");
    // Remove rules to unblock all outgoing traffic
    removeFirewallRule("block", "out", "all", "all", "all");
    }

    void logPanicModeEvent(){
        QFile logfile("panic_modelog.txt");
        if(logfile.open(QFile::WriteOnly | QFile::Append | QIODevice::Text)) {
            QTextStream out(&logfile);
            out << "Panic mode event occurred at " << QDateTime::currentDateTime().toString("yyyy");
    }

    void blockICMP(){
        QDBusMessage reply = firewallInterface->call("addRule""block", "in", "all", "icmp");
        if (reply.type() == QDBusMessage::ReplyMessage) {
            qDebug() << "ICMP blocked." ;
            } else{
                qCritical() <<"Error: unable to add ICMP block rule." ;
            }
        reply = firewallInterface->call("addRule", "block", "out", "all", "icmp");
        if (reply.type() == QDBusMessage::ReplyMessage) {
            qDebug() << "ICMP blocked." ;
            } else{
                qCritical() <<"Error: unable to add ICMP block rule." ;
            }
    }

    void unblockICMP(){
        QDBusMessage reply = firewallInterface->call("removeRule", "block", "in","all","icmp");
        if (reply.type() == QDBusMessage::ReplyMessage) {
            qDebug() << "ICMP unblocked." ;
            } else{
                qCritical() <<"Error: unable to remove ICMP block rule." ;
            }
        reply = firewallInterface->call("removerule","block","out","all","icmp");
        if (reply.type() == QDBusMessage::ReplyMessage) {
            qDebug() << "ICMP unblocked." ;
            } else{
                qCritical() <<"Error: unable to remove ICMP block rule." ;
            }
    }

    void ConfigureNat(const QString &externalInterface, const QString &internalNetwork) {
        // Create a new nat rule
        QString command = QString("sudo iptables -t nat -A POSTROUTING -o %1 -j MASQUERADE")
                                    .arg(internalNetwork)
                                    .ags(externalInterface);
        Qprocess process;
        process.start(command);
        process.waitForFinished();
        if (process.exitCode() == 0) {
            qDebug()<<"NAT Configured Successfully";
            } else
            {
                qCritial()<< "Error configuring NAT: " << process.errorString();
            }
    }

    void enableNat(const QString &externalInterface, const QString &internalNetwork) {
        // Enable NAT on the specified interface
        ConfigureNat(externallInterface, internalNetwork);

    }

    void disableNat(const QString &externalInterface, const QString &internalNetwork) {
        // Disable NAT on the specified interface
        QString command = QString("sudo iptables -t nat -D POSTROUTING -s %1 -j MASQUERADE").arg(ruleID);
        QProcess::execute(command );
        if (execute.exitCode() == 0) {
            qDebug()<<"NAT Disabled Successfully";
            } else
            {
                qCritial()<< "Error disabling NAT: " << execute.errorString();
            }
        }

    void getGeoIP(const QString &ip) {
        QUrl url(QString("http://ip-api.com/json/%1").arg(ip));
        QNetworkRequest request(url);
        QNetworkReply *reply = manager->get(request);
        connect(reply, &QNetworkReply::finished, this, &FirewallManager::onGeoLocationReceived);
    }

    void blockIPAddress(const QString &ipAddress) {
        cout << "Blocking IP address: " << ipAddress.toStdString() << endl;
        QFile file("blocked_ips.json");
        if (file.open(QIODevice::ReadWrite)) {
            QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
            QJsonObject obj = doc.object();
            QJsonArray blockedArray = obj["blocked_ips"].toArray();
            blockedArray.append(ipAddress);
            obj["blocked_ips"] = blockedArray;
            file.resize(0);
            file.write(QJsonDocument(obj).toJson());
            file.close();
            qDebug() << "Blocked IP: " << ipAddress;
        } else {
            qWarning() << "Failed to write to block list.";
        }
    }
    private slots:
    void onGeoLocationReceived() {
        QNetworkReply *reply = qobject_cast<QNetworkReply *>(sender());
        if (!reply || reply->error() != QNetworkReply::NoError) {
            qWarning() << "Error fetching geolocation data.";
            return;
        }

        QByteArray data = reply->readAll();
        QJsonDocument jsonDoc = QJsonDocument::fromJson(data);
        QJsonObject jsonObject = jsonDoc.object();
        QString country = jsonObject["country"].toString();
        QString city = jsonObject["city"].toString();

        qDebug() << "IP Country: " << country << ", City: " << city;
        if (country == "BlockedCountry") {
            blockIPAddress(jsonObject["query"].toString());
        }
        reply->deleteLater();
    }

    private:
        QDBusInterface *firewallInterface;
        QNetworkAccessManager *manager;
    };


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
// Mapping for tracking ongoing connections
QHash<QString, ConnectionState> connectionTable;

QString generateConnectionKey(const QString &sourceIP, const QString &sourcePort, const QString &destIP, const QString &destPort) {
    return sourceIP + ":" + sourcePort + " -> " + destIP + ":" + destPort;
}

void handlePacket(const QString &sourceIP, const QString &sourcePort, const QString &destIP, const QString &destPort, const QString &packetType) {
    QString connKey = generateConnectionKey(sourceIP, sourcePort, destIP, destPort);

    // Check connection state
    if (packetType == "SYN") {
        // New connection, add to connection table
        connectionTable[connKey] = { "NEW", sourceIP, destIP, sourcePort, destPort };
          // Extract features and analyze with neural network
            NetworkFeatures features = extractFeatures(connectionTable[connKey]);
            vector<double> inputVector = convertToVector(features);
            
            // Forward propagate through neural network
            neuralNetwork->forwardPropagate(inputVector);
            
            // Get the threat score from the neural network
            double threatScore = neuralNetwork->outputLayer[0][0];
            
            // Take action based on threat score
            if (threatScore > 0.8) {
                QString message = "High threat detected from " + sourceIP;
                blockIPAddress(sourceIP);
                logMessage(message);
                sendNotification(message);
            }
            else if (threatScore > 0.5) {
                analysisTrafficForAnomalies(connectionTable[connKey]);
            }
            
            // Add to training data for future learning
            vector<double> label = {threatScore > 0.5 ? 1.0 : 0.0};
            trainingData.push_back(inputVector);
            trainingLabels.push_back(label);
        }
        // ... (rest of your existing handlePacket code)
        qDebug() << "New connection from " << sourceIP << ":" << sourcePort << " to " << destIP << ":" << destPort;
    } else if (packetType == "ACK") {
        if (connectionTable.contains(connKey)) {
            connectionTable[connKey].state = "ESTABLISHED";
            qDebug() << "Connection established between " << sourceIP << ":" << sourcePort << " and " << destIP << ":" << destPort;
        }
    } else if (packetType == "FIN") {
        if (connectionTable.contains(connKey)) {
            connectionTable[connKey].state = "CLOSED";
            connectionTable.remove(connKey);  // Remove closed connection from table
            qDebug() << "Connection closed between " << sourceIP << ":" << sourcePort << " and " << destIP << ":" << destPort;
        }
    }
}
    // Example usage
    handlePacket("192.168.0.1", "12345", "192.168.0.2", "80", "SYN");
    handlePacket("192.168.0.1", "12345", "192.168.0.2", "80", "ACK");
    handlePacket("192.168.0.1", "12345", "192.168.0.2", "80", "FIN");

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
    QHash<QString, QString> loadConfig(const QString &configFilePath) {
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

    void addInterface(const QString &zone, const QString &interface){
        // Add a new interface to the configuration
        QDBusMessage reply = firewallInterface->call("addInterface",zone,interface);
        if(reply.type() == QDBusMessage::ReplyMessage) {
            cout<< "Interface"<<interface.toStdString()<<" added to zone " << zone.toStdString() << endl;
    } else {
         cerr << "Error: Unable to add interface " << interface.toStdString() << " to zone " << zone.toStdString() << endl;
       }
    }

    void changeZoneOfInterface(const QString &zone, const QString &interface){
        // Change the zone of an interface
        QDBusMessage reply = firewallInterface->call("changeZoneOfInterface",zone,interface);
        if(reply.type() == QDBusMessage::ReplyMessage) {
            cout<< "Interface"<<interface.toStdString()<<" changed to zone " << zone.toStdString() << zone.toStdString() << endl;
            } else {
                cerr << "Error: Unable to change zone of interface " << interface.toStdString() << endl;
                }
            
    }

    void ChangeZone(const QString &zone, const QString &interface){
        // Change the zone of an interface
        changeZoneOfInterface(zone,interface);
    }

    void removeInterface(const QString &zone, const QString &interface){
        // Remove an interface from the configuration
        QDBusMessage reply = firewallInterface->call("removeInterface",zone,interface);
        if(reply.type() = QDBusMessage::ReplyMessage) {
            cout<< "Interface"<<interface.toStdString()<<" removed from zone " << zone.toStdString() <<  " successfully." << endl;
        } else {
            cerr << "Error: Unable to remove interface " << interface.toStdString() << " from zone" << zone.toStdString() << endl;
                }
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

    void analysisTrafficForAnomalies(const ConnectionState &connection) {

        int connectionThreshold = 100;
        int connectioncount - connectionTable.count(connection.SourceIP);
        if (connectioncount > connectionThreshold) {
            qWarnning() << "Anomaly detected: " << connection.SourceIP << " has made " << connectioncount<< " connections in the last " << connectionThreshold << " seconds.";
            blockWebsite(connection.SourceIP);
            notify-send("Anomaly detected: High number of connections from IP " + connection.sourceIP);
            }
    }
   
    void detectPacketSizeAnomaly(int packetSize) {
        int averagesize = 512;
        int packetThreshold = 5;

        if (packetSize > averagesize * packetThreshold) {
            qWarning() << "Anomaly detected: Packet size " << packetSize;
            blockWebsite(connection.SourceIP);
            notify-send("Anomaly detected: Large packet size from IP " + connection.sourceIP);
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

    void trainNeuralNetwork() {
        if (trainingData.size() > 100) {  // Train after collecting enough samples
            neuralNetwork->train(trainingData, trainingLabels, 1000, 0.1);
            
            // Clear training data after successful training
            trainingData.clear();
            trainingLabels.clear();
            
            logMessage("Neural network training completed");
        }
    }

     void cleanupExpiredConnections() {
        QDateTime now = QDateTime::currentDateTime();
        
        for (auto it = connectionTable.begin(); it != connectionTable.end();) {
            if (it.value().lastUpdate.secsTo(now) > TIMEOUT_SECONDS) {
                // Before removing, add to training data
                NetworkFeatures features = extractFeatures(it.value());
                vector<double> inputVector = convertToVector(features);
                vector<double> label = {it.value().wasBlocked ? 1.0 : 0.0};
                
                trainingData.push_back(inputVector);
                trainingLabels.push_back(label);
                
                it = connectionTable.erase(it);
            } else {
                ++it;
            }
        }
        
        // Try to train the network after cleanup
        trainNeuralNetwork();
    }
};

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
    QString testIP = "8.8.8.8"; // Example IP to test geolocation
    manager.getGeoIP(testIP);
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
    firewallManager.initializeNeuralNetwork();  // Initialize the neural network

    // Check internet connectivity
    firewallManager.checkInternetConnectivity();


    // Set up a timer for periodic training
    QTimer trainingTimer;
    QObject::connect(&trainingTimer, &QTimer::timeout, 
                    &firewallManager, &FirewallManager::trainNeuralNetwork);
    trainingTimer.start(3600000);  

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






