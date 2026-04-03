// vanet-v2i-with-attacks-enhanced.cc
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/applications-module.h"
#include "ns3/netanim-module.h"
#include "ns3/flow-monitor-module.h"
#include <fstream>
#include <sstream>
#include <vector>
#include <map>
#include <string>
#include <algorithm>
#include <set>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("VanetV2IWithAttacks");

// ================== DATA STRUCTURES ==================

struct VanetData {
    uint32_t vehicle_id;
    std::string timestamp;
    double latitude;
    double longitude;
    double speed;
    double acceleration;
    double direction;
    uint32_t lane_id;
    double packet_loss_rate;
    double signal_strength;
    uint32_t message_frequency;
    double data_volume;
    double latency;
    std::string weather_condition;
    uint32_t traffic_density;
    std::string road_type;
    double rsu_distance;
    uint32_t threat_type;  // 0=Normal, 1=Sybil, 2=DoS, 3=FalseData
};

// ================== CSV PARSER ==================

class CsvDataParser {
public:
    std::vector<VanetData> ParseCsvFile(const std::string& filename) {
        std::vector<VanetData> dataPoints;
        std::ifstream file(filename);
        
        if (!file.is_open()) {
            std::cerr << "Error: Could not open file " << filename << std::endl;
            return dataPoints;
        }
        
        std::string line;
        // Skip header
        std::getline(file, line);
        
        int lineNumber = 1;
        while (std::getline(file, line)) {
            lineNumber++;
            try {
                VanetData data = ParseLine(line);
                dataPoints.push_back(data);
            } catch (const std::exception& e) {
                std::cerr << "Error parsing line " << lineNumber << ": " << e.what() << std::endl;
            }
        }
        
        file.close();
        return dataPoints;
    }
    
    std::set<uint32_t> GetUniqueVehicleIds(const std::vector<VanetData>& data) {
        std::set<uint32_t> uniqueIds;
        for (const auto& entry : data) {
            uniqueIds.insert(entry.vehicle_id);
        }
        return uniqueIds;
    }
    
private:
    VanetData ParseLine(const std::string& line) {
        VanetData data;
        std::stringstream ss(line);
        std::string cell;
        int column = 0;
        
        while (std::getline(ss, cell, ',')) {
            try {
                switch(column) {
                    case 0: data.vehicle_id = std::stoi(cell); break;
                    case 1: data.timestamp = cell; break;
                    case 2: data.latitude = std::stod(cell); break;
                    case 3: data.longitude = std::stod(cell); break;
                    case 4: data.speed = std::stod(cell); break;
                    case 5: data.acceleration = std::stod(cell); break;
                    case 6: data.direction = std::stod(cell); break;
                    case 7: data.lane_id = std::stoi(cell); break;
                    case 8: data.packet_loss_rate = std::stod(cell); break;
                    case 9: data.signal_strength = std::stod(cell); break;
                    case 10: data.message_frequency = std::stoi(cell); break;
                    case 11: data.data_volume = std::stod(cell); break;
                    case 12: data.latency = std::stod(cell); break;
                    case 13: data.weather_condition = cell; break;
                    case 14: data.traffic_density = std::stoi(cell); break;
                    case 15: data.road_type = cell; break;
                    case 16: data.rsu_distance = std::stod(cell); break;
                    case 17: data.threat_type = std::stoi(cell); break;
                }
            } catch (...) {
                // Handle parsing errors for individual fields
            }
            column++;
        }
        
        return data;
    }
};

// ================== ATTACK SIMULATOR APPLICATION ==================

class AttackSimulatorApp : public Application {
public:
    static TypeId GetTypeId() {
        static TypeId tid = TypeId("AttackSimulatorApp")
            .SetParent<Application>()
            .SetGroupName("Applications")
            .AddConstructor<AttackSimulatorApp>();
        return tid;
    }
    
    AttackSimulatorApp() : m_socket(0), m_dataIndex(0) {}
    
    void SetupAttack(const std::vector<VanetData>& vehicleData, Ipv4Address dest, uint16_t port) {
        m_vehicleData = vehicleData;
        m_peerAddress = dest;
        m_peerPort = port;
    }
    
protected:
    virtual void StartApplication() {
        m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
        m_socket->Bind();
        m_socket->Connect(InetSocketAddress(m_peerAddress, m_peerPort));
        
        // Schedule first packet
        ScheduleNextTransmit();
    }
    
    virtual void StopApplication() {
        if (m_sendEvent.IsRunning()) {
            Simulator::Cancel(m_sendEvent);
        }
        if (m_socket) {
            m_socket->Close();
            m_socket = 0;
        }
    }
    
private:
    void ScheduleNextTransmit() {
        if (m_dataIndex >= m_vehicleData.size()) {
            m_dataIndex = 0;  // Loop back to beginning
        }
        
        VanetData currentData = m_vehicleData[m_dataIndex];
        double interval;
        
        // Adjust transmission rate based on attack type and message frequency
        switch(currentData.threat_type) {
            case 0: // Normal traffic
                interval = (currentData.message_frequency > 0) ? 
                          (1.0 / currentData.message_frequency) : 0.1;
                break;
            case 1: // Sybil - moderate frequency
                interval = 0.05;  // 20 packets/sec
                break;
            case 2: // DoS - flood the network
                interval = 0.01;  // 100 packets/sec
                break;
            case 3: // False Data - normal frequency but bad data
                interval = 0.1;
                break;
            default:
                interval = 0.1;
        }
        
        m_sendEvent = Simulator::Schedule(Seconds(interval), 
                                         &AttackSimulatorApp::SendPacket, this);
    }
    
    void SendPacket() {
        if (m_dataIndex >= m_vehicleData.size()) {
            m_dataIndex = 0;
        }
        
        VanetData currentData = m_vehicleData[m_dataIndex++];
        
        // Create packet with size based on data_volume from CSV
        uint32_t packetSize = static_cast<uint32_t>(currentData.data_volume * 10);
        
        // For DoS attacks, send larger packets
        if (currentData.threat_type == 2) {
            packetSize *= 2;  // Double size for DoS
        }
        
        // Create packet
        Ptr<Packet> packet = Create<Packet>(packetSize);
        
        // Simulate packet loss based on CSV data
        double random = ((double) rand() / RAND_MAX);
        if (random > currentData.packet_loss_rate) {
            m_socket->Send(packet);
        }
        
        // Schedule next transmission
        ScheduleNextTransmit();
    }
    
    std::vector<VanetData> m_vehicleData;
    Ptr<Socket> m_socket;
    Ipv4Address m_peerAddress;
    uint16_t m_peerPort;
    EventId m_sendEvent;
    size_t m_dataIndex;
};

// ================== MAIN SIMULATION ==================

int main(int argc, char *argv[]) {
    // ================== DEFAULT PARAMETERS ==================
    uint32_t nVehicles = 0;  // 0 means auto-detect from CSV
    double simTime = 60.0;
    std::string csvFile = "enhanced_vanet_dataset.csv";
    bool useCSVData = true;
    bool verbose = false;
    bool tracing = true;
    double txPower = 23.0;
    uint32_t maxVehicles = 100;  // Maximum vehicles to simulate
    
    // ================== COMMAND LINE PARSING ==================
    CommandLine cmd(__FILE__);
    cmd.AddValue("nVehicles", "Number of vehicles (0=auto-detect)", nVehicles);
    cmd.AddValue("simTime", "Simulation time in seconds", simTime);
    cmd.AddValue("csvFile", "CSV dataset file path", csvFile);
    cmd.AddValue("useCSV", "Use CSV data for attack simulation", useCSVData);
    cmd.AddValue("verbose", "Enable logging", verbose);
    cmd.AddValue("tracing", "Enable pcap tracing", tracing);
    cmd.AddValue("txPower", "Transmission power in dBm", txPower);
    cmd.AddValue("maxVehicles", "Maximum vehicles to simulate", maxVehicles);
    cmd.Parse(argc, argv);
    
    // Enable logging if requested
    if (verbose) {
        LogComponentEnable("VanetV2IWithAttacks", LOG_LEVEL_INFO);
    }
    
    // ================== LOAD AND ANALYZE CSV DATA ==================
    std::vector<VanetData> csvData;
    std::map<uint32_t, std::vector<VanetData>> vehicleDataMap;
    std::set<uint32_t> uniqueVehicleIds;
    
    if (useCSVData) {
        std::cout << "\n========================================" << std::endl;
        std::cout << "Loading CSV data from: " << csvFile << std::endl;
        std::cout << "========================================" << std::endl;
        
        CsvDataParser parser;
        csvData = parser.ParseCsvFile(csvFile);
        
        if (csvData.empty()) {
            std::cerr << "Error: No data loaded from CSV file!" << std::endl;
            return 1;
        }
        
        // Get unique vehicle IDs
        uniqueVehicleIds = parser.GetUniqueVehicleIds(csvData);
        
        // Group data by vehicle ID
        for (const auto& data : csvData) {
            vehicleDataMap[data.vehicle_id].push_back(data);
        }
        
        // Auto-detect number of vehicles if not specified
        if (nVehicles == 0) {
            nVehicles = uniqueVehicleIds.size();
            std::cout << "Auto-detected " << nVehicles << " unique vehicles in dataset" << std::endl;
        } else {
            std::cout << "Dataset has " << uniqueVehicleIds.size() 
                     << " unique vehicles, using " << nVehicles << " for simulation" << std::endl;
        }
        
        // Limit to maxVehicles if necessary
        if (nVehicles > maxVehicles) {
            std::cout << "Limiting simulation to " << maxVehicles << " vehicles (max allowed)" << std::endl;
            nVehicles = maxVehicles;
        }
        
        // Analyze attack distribution
        int normalCount = 0, sybilCount = 0, dosCount = 0, falseDataCount = 0;
        for (const auto& data : csvData) {
            switch(data.threat_type) {
                case 0: normalCount++; break;
                case 1: sybilCount++; break;
                case 2: dosCount++; break;
                case 3: falseDataCount++; break;
            }
        }
        
        std::cout << "\n--- Dataset Statistics ---" << std::endl;
        std::cout << "Total data points: " << csvData.size() << std::endl;
        std::cout << "Unique vehicles: " << uniqueVehicleIds.size() << std::endl;
        std::cout << "Vehicles to simulate: " << nVehicles << std::endl;
        
        std::cout << "\n--- Attack Distribution ---" << std::endl;
        std::cout << "Normal Traffic: " << normalCount 
                  << " (" << (100.0*normalCount/csvData.size()) << "%)" << std::endl;
        std::cout << "Sybil Attacks: " << sybilCount 
                  << " (" << (100.0*sybilCount/csvData.size()) << "%)" << std::endl;
        std::cout << "DoS Attacks: " << dosCount 
                  << " (" << (100.0*dosCount/csvData.size()) << "%)" << std::endl;
        std::cout << "False Data Attacks: " << falseDataCount 
                  << " (" << (100.0*falseDataCount/csvData.size()) << "%)" << std::endl;
        std::cout << "========================================\n" << std::endl;
    } else {
        // Default to 10 vehicles if not using CSV
        if (nVehicles == 0) {
            nVehicles = 10;
        }
        std::cout << "Not using CSV data, creating " << nVehicles << " vehicles" << std::endl;
    }
    
    // ================== CREATE NETWORK NODES ==================
    NodeContainer vehicles;
    vehicles.Create(nVehicles);
    
    NodeContainer baseStation;
    baseStation.Create(1);
    
    NodeContainer allNodes;
    allNodes.Add(vehicles);
    allNodes.Add(baseStation);
    
    // ================== SETUP WIFI 802.11p ==================
    YansWifiChannelHelper channel;
    channel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    channel.AddPropagationLoss("ns3::LogDistancePropagationLossModel",
                              "Exponent", DoubleValue(2.5),
                              "ReferenceLoss", DoubleValue(40.0),
                              "ReferenceDistance", DoubleValue(1.0));
    
    YansWifiPhyHelper phy;
    phy.SetChannel(channel.Create());
    phy.Set("TxPowerStart", DoubleValue(txPower));
    phy.Set("TxPowerEnd", DoubleValue(txPower));
    phy.Set("TxGain", DoubleValue(1.0));
    phy.Set("RxGain", DoubleValue(1.0));
    phy.Set("RxNoiseFigure", DoubleValue(7.0));
    phy.SetPcapDataLinkType(WifiPhyHelper::DLT_IEEE802_11);
    
    WifiMacHelper mac;
    mac.SetType("ns3::AdhocWifiMac");
    
    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211p);
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                "DataMode", StringValue("OfdmRate6MbpsBW10MHz"),
                                "ControlMode", StringValue("OfdmRate6MbpsBW10MHz"));
    
    NetDeviceContainer vehicleDevices = wifi.Install(phy, mac, vehicles);
    NetDeviceContainer baseStationDevice = wifi.Install(phy, mac, baseStation);
    
    NetDeviceContainer allDevices;
    allDevices.Add(vehicleDevices);
    allDevices.Add(baseStationDevice);
    
    // ================== SETUP MOBILITY ==================
    MobilityHelper vehicleMobility;
    
    if (useCSVData && !csvData.empty()) {
        // Use positions from CSV data
        Ptr<ListPositionAllocator> posAlloc = CreateObject<ListPositionAllocator>();
        
        // Create iterator for unique vehicle IDs
        auto idIterator = uniqueVehicleIds.begin();
        
        for (uint32_t i = 0; i < nVehicles && idIterator != uniqueVehicleIds.end(); ++i, ++idIterator) {
            uint32_t vehicleId = *idIterator;
            
            if (vehicleDataMap.find(vehicleId) != vehicleDataMap.end() && 
                !vehicleDataMap[vehicleId].empty()) {
                
                // Convert lat/long to simulation coordinates
                // Scale and offset for reasonable simulation area
                double x = (vehicleDataMap[vehicleId][0].longitude + 120.0) * 10000;
                double y = (vehicleDataMap[vehicleId][0].latitude - 35.0) * 10000;
                double z = 0.0;
                
                posAlloc->Add(Vector(x, y, z));
            } else {
                // Default position if data not found
                posAlloc->Add(Vector(i * 100.0, 100.0, 0.0));
            }
        }
        
        vehicleMobility.SetPositionAllocator(posAlloc);
        vehicleMobility.SetMobilityModel("ns3::ConstantVelocityMobilityModel");
        vehicleMobility.Install(vehicles);
        
        // Set velocities based on CSV speed data
        idIterator = uniqueVehicleIds.begin();
        for (uint32_t i = 0; i < nVehicles && idIterator != uniqueVehicleIds.end(); ++i, ++idIterator) {
            uint32_t vehicleId = *idIterator;
            
            Ptr<ConstantVelocityMobilityModel> mob = 
                vehicles.Get(i)->GetObject<ConstantVelocityMobilityModel>();
            
            if (vehicleDataMap.find(vehicleId) != vehicleDataMap.end() && 
                !vehicleDataMap[vehicleId].empty()) {
                // Convert speed from km/h to m/s and apply direction
                double speed = vehicleDataMap[vehicleId][0].speed / 3.6;
                double direction = vehicleDataMap[vehicleId][0].direction * M_PI / 180.0;
                
                double vx = speed * cos(direction);
                double vy = speed * sin(direction);
                
                mob->SetVelocity(Vector(vx, vy, 0.0));
            }
        }
    } else {
        // Default grid positions if no CSV data
        vehicleMobility.SetPositionAllocator("ns3::GridPositionAllocator",
                                            "MinX", DoubleValue(0.0),
                                            "MinY", DoubleValue(100.0),
                                            "DeltaX", DoubleValue(100.0),
                                            "DeltaY", DoubleValue(0.0),
                                            "GridWidth", UintegerValue(nVehicles),
                                            "LayoutType", StringValue("RowFirst"));
        vehicleMobility.SetMobilityModel("ns3::ConstantVelocityMobilityModel");
        vehicleMobility.Install(vehicles);
        
        // Set default velocities
        for (uint32_t i = 0; i < vehicles.GetN(); ++i) {
            Ptr<ConstantVelocityMobilityModel> mob = 
                vehicles.Get(i)->GetObject<ConstantVelocityMobilityModel>();
            double speed = 20.0 + (i % 3) * 5.0;  // 20-30 m/s
            mob->SetVelocity(Vector(speed, 0.0, 0.0));
        }
    }
    
    // Base station mobility (static)
    MobilityHelper baseStationMobility;
    Ptr<ListPositionAllocator> bsPositionAlloc = CreateObject<ListPositionAllocator>();
    bsPositionAlloc->Add(Vector(500.0, 100.0, 15.0));  // Elevated at 15m
    baseStationMobility.SetPositionAllocator(bsPositionAlloc);
    baseStationMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    baseStationMobility.Install(baseStation);
    
    // ================== SETUP INTERNET STACK ==================
    InternetStackHelper internet;
    internet.Install(allNodes);
    
    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = ipv4.Assign(allDevices);
    
    Ipv4Address baseStationAddr = interfaces.GetAddress(nVehicles);
    
    // ================== PRINT CONFIGURATION ==================
    std::cout << "\n========================================" << std::endl;
    std::cout << "  VANET V2I ATTACK SIMULATION CONFIG" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Using CSV Data: " << (useCSVData ? "YES" : "NO") << std::endl;
    std::cout << "CSV File: " << csvFile << std::endl;
    std::cout << "Simulating Vehicles: " << nVehicles << std::endl;
    std::cout << "Base Station IP: " << baseStationAddr << std::endl;
    std::cout << "TX Power: " << txPower << " dBm" << std::endl;
    std::cout << "Simulation Time: " << simTime << " seconds" << std::endl;
    std::cout << "PCAP Tracing: " << (tracing ? "ENABLED" : "DISABLED") << std::endl;
    std::cout << "========================================\n" << std::endl;
    
    // ================== SETUP APPLICATIONS ==================
    uint16_t baseStationPort = 9999;
    
    // Install PacketSink on base station
    PacketSinkHelper packetSinkHelper("ns3::UdpSocketFactory",
                                      InetSocketAddress(Ipv4Address::GetAny(), baseStationPort));
    ApplicationContainer baseStationApp = packetSinkHelper.Install(baseStation.Get(0));
    baseStationApp.Start(Seconds(0.0));
    baseStationApp.Stop(Seconds(simTime + 1));
    
    // Install attack simulators on vehicles
    ApplicationContainer vehicleApps;
    
    if (useCSVData && !vehicleDataMap.empty()) {
        auto idIterator = uniqueVehicleIds.begin();
        
        for (uint32_t i = 0; i < nVehicles && idIterator != uniqueVehicleIds.end(); ++i, ++idIterator) {
            uint32_t vehicleId = *idIterator;
            
            if (vehicleDataMap.find(vehicleId) != vehicleDataMap.end()) {
                // Create custom application for this vehicle
                Ptr<AttackSimulatorApp> app = CreateObject<AttackSimulatorApp>();
                app->SetupAttack(vehicleDataMap[vehicleId], baseStationAddr, baseStationPort);
                
                vehicles.Get(i)->AddApplication(app);
                app->SetStartTime(Seconds(1.0 + i * 0.01));  // Stagger start times
                app->SetStopTime(Seconds(simTime));
                
                vehicleApps.Add(app);
            }
        }
    } else {
        // Default OnOff applications if no CSV data
        for (uint32_t i = 0; i < vehicles.GetN(); ++i) {
            OnOffHelper onoff("ns3::UdpSocketFactory",
                             InetSocketAddress(baseStationAddr, baseStationPort));
            
            onoff.SetAttribute("DataRate", StringValue("2048kb/s"));
            onoff.SetAttribute("PacketSize", UintegerValue(1024));
            onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
            onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
            
            ApplicationContainer app = onoff.Install(vehicles.Get(i));
            app.Start(Seconds(1.0 + i * 0.1));
            app.Stop(Seconds(simTime));
            
            vehicleApps.Add(app);
        }
    }
    
    // ================== SETUP ROUTING ==================
    Ipv4GlobalRoutingHelper::PopulateRoutingTables();
    
    // ================== ENABLE TRACING ==================
    if (tracing) {
        phy.EnablePcap("vanet-attack-basestation", baseStationDevice.Get(0), true);
        if (vehicleDevices.GetN() > 0) {
            phy.EnablePcap("vanet-attack-vehicle", vehicleDevices.Get(0), true);
        }
    }
    
    // ================== SETUP ANIMATION ==================
    AnimationInterface anim("vanet-attack-animation.xml");
    
    // Configure vehicle nodes
    auto idIterator = uniqueVehicleIds.begin();
    for (uint32_t i = 0; i < vehicles.GetN() && idIterator != uniqueVehicleIds.end(); ++i, ++idIterator) {
        std::string desc = "V" + std::to_string(*idIterator);
        anim.UpdateNodeDescription(vehicles.Get(i), desc);
        
        // Color based on predominant attack type
        if (useCSVData && vehicleDataMap.find(*idIterator) != vehicleDataMap.end()) {
            uint32_t threatType = vehicleDataMap[*idIterator][0].threat_type;
            switch(threatType) {
                case 0: anim.UpdateNodeColor(vehicles.Get(i), 0, 255, 0); break;    // Green for normal
                case 1: anim.UpdateNodeColor(vehicles.Get(i), 255, 255, 0); break;  // Yellow for Sybil
                case 2: anim.UpdateNodeColor(vehicles.Get(i), 255, 0, 0); break;    // Red for DoS
                case 3: anim.UpdateNodeColor(vehicles.Get(i), 255, 128, 0); break;  // Orange for False Data
            }
        } else {
            anim.UpdateNodeColor(vehicles.Get(i), 0, 255, 0);  // Default green
        }
        
        anim.UpdateNodeSize(vehicles.Get(i)->GetId(), 5, 5);
    }
    
    // Configure base station
    anim.UpdateNodeDescription(baseStation.Get(0), "RSU");
    anim.UpdateNodeColor(baseStation.Get(0), 0, 0, 255);  // Blue
    anim.UpdateNodeSize(baseStation.Get(0)->GetId(), 20, 20);
    
    // ================== SETUP FLOW MONITOR ==================
    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();
    
    // ================== RUN SIMULATION ==================
    
    // Schedule progress updates
    for (double t = 10.0; t < simTime; t += 10.0) {
        Simulator::Schedule(Seconds(t), [t, simTime]() {
            std::cout << "Simulation Progress: " << (int)(100.0 * t / simTime) 
                     << "% (" << t << "/" << simTime << " seconds)" << std::endl;
        });
    }
    
    std::cout << "Starting simulation..." << std::endl;
    
    Simulator::Stop(Seconds(simTime + 1));
    Simulator::Run();
    
    // ================== COLLECT AND ANALYZE STATISTICS ==================
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "       SIMULATION RESULTS" << std::endl;
    std::cout << "========================================" << std::endl;
    
    // Get PacketSink statistics
    Ptr<PacketSink> sink = DynamicCast<PacketSink>(baseStationApp.Get(0));
    uint32_t totalBytesReceived = sink->GetTotalRx();
    
    std::cout << "\n--- BASE STATION STATISTICS ---" << std::endl;
    std::cout << "Total Data Received: " << totalBytesReceived / 1024.0 << " KB" << std::endl;
    std::cout << "Total Data Received: " << totalBytesReceived / (1024.0 * 1024.0) << " MB" << std::endl;
    std::cout << "Average Throughput: " << (totalBytesReceived * 8.0) / (simTime * 1000000.0) 
             << " Mbps" << std::endl;
    
    // Analyze flow statistics
    monitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());
    FlowMonitor::FlowStatsContainer stats = monitor->GetFlowStats();
    
    // Categorize flows by performance metrics
    double totalNormalDelay = 0, totalAttackDelay = 0;
    uint32_t normalFlows = 0, attackFlows = 0;
    double normalThroughput = 0, attackThroughput = 0;
    uint32_t totalTxPackets = 0, totalRxPackets = 0;
    
    std::cout << "\n--- PER-FLOW ANALYSIS ---" << std::endl;
    
    for (const auto& flow : stats) {
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(flow.first);
        
        if (flow.second.rxPackets > 0) {
            double avgDelay = flow.second.delaySum.GetMilliSeconds() / flow.second.rxPackets;
            double pdr = (flow.second.rxPackets * 100.0) / flow.second.txPackets;
            double throughput = flow.second.rxBytes * 8.0 / simTime / 1000.0;  // kbps
            
            totalTxPackets += flow.second.txPackets;
            totalRxPackets += flow.second.rxPackets;
            
            // Classify as attack-affected if high delay or low PDR
            bool isAttackAffected = (avgDelay > 50.0 || pdr < 80.0);
            
            if (isAttackAffected) {
                totalAttackDelay += avgDelay;
                attackFlows++;
                attackThroughput += throughput;
            } else {
                totalNormalDelay += avgDelay;
                normalFlows++;
                normalThroughput += throughput;
            }
        }
    }
    
    // Print categorized results
    std::cout << "\n--- ATTACK IMPACT ANALYSIS ---" << std::endl;
    
    if (normalFlows > 0) {
        std::cout << "\nNormal Traffic Performance:" << std::endl;
        std::cout << "  Flows: " << normalFlows << std::endl;
        std::cout << "  Average Delay: " << totalNormalDelay/normalFlows << " ms" << std::endl;
        std::cout << "  Total Throughput: " << normalThroughput << " kbps" << std::endl;
    }
    
    if (attackFlows > 0) {
        std::cout << "\nAttack-Affected Traffic:" << std::endl;
        std::cout << "  Flows: " << attackFlows << std::endl;
        std::cout << "  Average Delay: " << totalAttackDelay/attackFlows << " ms" << std::endl;
        std::cout << "  Total Throughput: " << attackThroughput << " kbps" << std::endl;
        
        if (normalFlows > 0) {
            double delayIncrease = ((totalAttackDelay/attackFlows) / (totalNormalDelay/normalFlows) - 1) * 100;
            double throughputDecrease = (1 - (attackThroughput/attackFlows) / (normalThroughput/normalFlows)) * 100;
            
            std::cout << "\nPerformance Degradation:" << std::endl;
            std::cout << "  Delay Increase: " << delayIncrease << "%" << std::endl;
            std::cout << "  Throughput Decrease: " << throughputDecrease << "%" << std::endl;
        }
    }
    
    // Overall statistics
    std::cout << "\n--- OVERALL NETWORK STATISTICS ---" << std::endl;
    std::cout << "Total TX Packets: " << totalTxPackets << std::endl;
    std::cout << "Total RX Packets: " << totalRxPackets << std::endl;
    
    if (totalTxPackets > 0) {
        std::cout << "Overall Packet Delivery Ratio: " 
                 << (totalRxPackets * 100.0) / totalTxPackets << "%" << std::endl;
    }
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "    Simulation Completed Successfully!" << std::endl;
    std::cout << "========================================" << std::endl;
    
    // Clean up
    Simulator::Destroy();
    
    return 0;
}