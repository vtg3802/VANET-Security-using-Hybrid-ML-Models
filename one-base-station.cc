
 #include "ns3/core-module.h"
 #include "ns3/network-module.h"
 #include "ns3/internet-module.h"
 #include "ns3/mobility-module.h"
 #include "ns3/wifi-module.h"
 #include "ns3/applications-module.h"
 #include "ns3/netanim-module.h"
 #include "ns3/flow-monitor-module.h"
 
 using namespace ns3;
 
 NS_LOG_COMPONENT_DEFINE("VanetV2I");
 
 int main(int argc, char *argv[])
 {
     // ================== SIMULATION PARAMETERS ==================
     uint32_t nVehicles = 10;
     double simTime = 60.0;
     bool verbose = false;
     bool tracing = true;
     double txPower = 23.0;  // Transmission power in dBm
     std::string dataRate = "2048kb/s";  // Data rate for vehicle uploads
     uint32_t packetSize = 1024;  // Packet size in bytes
     double interval = 0.1;  // Packet interval in seconds (10 packets/sec)
     
     // Command line arguments
     CommandLine cmd(__FILE__);
     cmd.AddValue("nVehicles", "Number of vehicles", nVehicles);
     cmd.AddValue("simTime", "Simulation time in seconds", simTime);
     cmd.AddValue("verbose", "Enable logging", verbose);
     cmd.AddValue("tracing", "Enable pcap tracing", tracing);
     cmd.AddValue("txPower", "Transmission power in dBm", txPower);
     cmd.AddValue("dataRate", "Application data rate", dataRate);
     cmd.AddValue("packetSize", "Size of packets in bytes", packetSize);
     cmd.AddValue("interval", "Packet interval in seconds", interval);
     cmd.Parse(argc, argv);
     
     // Enable logging if requested
     if (verbose)
     {
         LogComponentEnable("VanetV2I", LOG_LEVEL_INFO);
         LogComponentEnable("OnOffApplication", LOG_LEVEL_INFO);
         LogComponentEnable("PacketSink", LOG_LEVEL_INFO);
     }
     
     // ================== CREATE NODES ==================
     
     // Create vehicle nodes
     NodeContainer vehicles;
     vehicles.Create(nVehicles);
     
     // Create base station (RSU/Infrastructure)
     NodeContainer baseStation;
     baseStation.Create(1);
     
     // Container for all nodes
     NodeContainer allNodes;
     allNodes.Add(vehicles);
     allNodes.Add(baseStation);
     
     // ================== SETUP WIFI 802.11p ==================
     
     // Setup channel with realistic propagation
     YansWifiChannelHelper channel;
     channel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
     channel.AddPropagationLoss("ns3::LogDistancePropagationLossModel",
                               "Exponent", DoubleValue(2.5),  // Path loss exponent
                               "ReferenceLoss", DoubleValue(40.0),
                               "ReferenceDistance", DoubleValue(1.0));
     
     // Setup PHY layer
     YansWifiPhyHelper phy;
     phy.SetChannel(channel.Create());
     phy.Set("TxPowerStart", DoubleValue(txPower));
     phy.Set("TxPowerEnd", DoubleValue(txPower));
     phy.Set("TxGain", DoubleValue(1.0));
     phy.Set("RxGain", DoubleValue(1.0));
     phy.Set("RxNoiseFigure", DoubleValue(7.0));
     phy.SetPcapDataLinkType(WifiPhyHelper::DLT_IEEE802_11);
     
     // Setup MAC layer for 802.11p
     WifiMacHelper mac;
     mac.SetType("ns3::AdhocWifiMac");  // Ad-hoc mode for 802.11p
     
     // Setup WiFi with 802.11p standard
     WifiHelper wifi;
     wifi.SetStandard(WIFI_STANDARD_80211p);
     wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                 "DataMode", StringValue("OfdmRate6MbpsBW10MHz"),
                                 "ControlMode", StringValue("OfdmRate6MbpsBW10MHz"));
     
     // Install WiFi devices on all nodes
     NetDeviceContainer vehicleDevices = wifi.Install(phy, mac, vehicles);
     NetDeviceContainer baseStationDevice = wifi.Install(phy, mac, baseStation);
     
     NetDeviceContainer allDevices;
     allDevices.Add(vehicleDevices);
     allDevices.Add(baseStationDevice);
     
     // ================== SETUP MOBILITY ==================
     
     // Mobility for vehicles - Highway scenario
     MobilityHelper vehicleMobility;
     
     // Initial positions - vehicles spread along a 1km highway segment
     vehicleMobility.SetPositionAllocator("ns3::GridPositionAllocator",
                                          "MinX", DoubleValue(0.0),
                                          "MinY", DoubleValue(100.0),  // Highway at y=100
                                          "DeltaX", DoubleValue(100.0),  // 100m spacing
                                          "DeltaY", DoubleValue(0.0),
                                          "GridWidth", UintegerValue(nVehicles),
                                          "LayoutType", StringValue("RowFirst"));
     
     // Constant velocity model for highway movement
     vehicleMobility.SetMobilityModel("ns3::ConstantVelocityMobilityModel");
     vehicleMobility.Install(vehicles);
     
     // Set vehicle velocities (20-30 m/s ≈ 72-108 km/h)
     for (uint32_t i = 0; i < vehicles.GetN(); ++i)
     {
         Ptr<ConstantVelocityMobilityModel> mob = vehicles.Get(i)->GetObject<ConstantVelocityMobilityModel>();
         double speed = 20.0 + (i % 3) * 5.0;  // Varying speeds
         mob->SetVelocity(Vector(speed, 0.0, 0.0));  // Moving along X-axis
     }
     
     // Mobility for base station - Static at center of coverage area
     MobilityHelper baseStationMobility;
     Ptr<ListPositionAllocator> bsPositionAlloc = CreateObject<ListPositionAllocator>();
     bsPositionAlloc->Add(Vector(500.0, 100.0, 15.0));  // Center position, elevated at 15m
     baseStationMobility.SetPositionAllocator(bsPositionAlloc);
     baseStationMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
     baseStationMobility.Install(baseStation);
     
     // ================== SETUP INTERNET STACK ==================
     
     InternetStackHelper internet;
     internet.Install(allNodes);
     
     // Assign IP addresses
     Ipv4AddressHelper ipv4;
     ipv4.SetBase("10.1.1.0", "255.255.255.0");
     Ipv4InterfaceContainer interfaces = ipv4.Assign(allDevices);
     
     // Get base station IP address
     Ipv4Address baseStationAddr = interfaces.GetAddress(nVehicles);  // Last address is base station
     
     // ================== PRINT CONFIGURATION ==================
     
     std::cout << "\n========================================" << std::endl;
     std::cout << "    VANET V2I Simulation Configuration" << std::endl;
     std::cout << "========================================" << std::endl;
     std::cout << "Vehicles: " << nVehicles << std::endl;
     std::cout << "Base Station IP: " << baseStationAddr << std::endl;
     std::cout << "TX Power: " << txPower << " dBm" << std::endl;
     std::cout << "Data Rate: " << dataRate << std::endl;
     std::cout << "Packet Size: " << packetSize << " bytes" << std::endl;
     std::cout << "Packet Interval: " << interval << " seconds" << std::endl;
     std::cout << "Simulation Time: " << simTime << " seconds" << std::endl;
     std::cout << "----------------------------------------" << std::endl;
     
     // Print vehicle IPs
     std::cout << "\nVehicle IP Addresses:" << std::endl;
     for (uint32_t i = 0; i < nVehicles; ++i)
     {
         std::cout << "  Vehicle " << i << ": " << interfaces.GetAddress(i) << std::endl;
     }
     std::cout << "========================================\n" << std::endl;
     
     // ================== SETUP APPLICATIONS ==================
     
     uint16_t baseStationPort = 9999;
     
     // 1. Install PacketSink on base station to receive data
     PacketSinkHelper packetSinkHelper("ns3::UdpSocketFactory",
                                       InetSocketAddress(Ipv4Address::GetAny(), baseStationPort));
     ApplicationContainer baseStationApp = packetSinkHelper.Install(baseStation.Get(0));
     baseStationApp.Start(Seconds(0.0));
     baseStationApp.Stop(Seconds(simTime + 1));
     
     // 2. Install OnOff application on vehicles to send data to base station
     ApplicationContainer vehicleApps;
     
     for (uint32_t i = 0; i < vehicles.GetN(); ++i)
     {
         // Each vehicle sends data to the base station
         OnOffHelper onoff("ns3::UdpSocketFactory",
                          InetSocketAddress(baseStationAddr, baseStationPort));
         
         onoff.SetAttribute("DataRate", StringValue(dataRate));
         onoff.SetAttribute("PacketSize", UintegerValue(packetSize));
         onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
         onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
         
         ApplicationContainer app = onoff.Install(vehicles.Get(i));
         
         // Stagger start times slightly to avoid collisions
         app.Start(Seconds(1.0 + i * 0.1));
         app.Stop(Seconds(simTime));
         
         vehicleApps.Add(app);
     }
     
     // ================== SETUP ROUTING ==================
     
     Ipv4GlobalRoutingHelper::PopulateRoutingTables();
     
     // ================== ENABLE TRACING ==================
     
     if (tracing)
     {
         // Trace base station
         phy.EnablePcap("vanet-v2i-basestation", baseStationDevice.Get(0), true);
         
         // Trace first vehicle
         phy.EnablePcap("vanet-v2i-vehicle", vehicleDevices.Get(0), true);
     }
     
     // ================== SETUP ANIMATION ==================
     
     AnimationInterface anim("vanet-v2i-animation.xml");
     
     // Configure vehicle nodes
     for (uint32_t i = 0; i < vehicles.GetN(); ++i)
     {
         anim.UpdateNodeDescription(vehicles.Get(i), "V" + std::to_string(i));
         anim.UpdateNodeColor(vehicles.Get(i), 0, 255, 0);  // Green
         anim.UpdateNodeSize(vehicles.Get(i)->GetId(), 5, 5);
     }
     
     // Configure base station node
     anim.UpdateNodeDescription(baseStation.Get(0), "BASE-STATION");
     anim.UpdateNodeColor(baseStation.Get(0), 255, 0, 0);  // Red
     anim.UpdateNodeSize(baseStation.Get(0)->GetId(), 20, 20);  // Larger size
     
     // ================== SETUP FLOW MONITOR ==================
     
     FlowMonitorHelper flowmon;
     Ptr<FlowMonitor> monitor = flowmon.InstallAll();
     
     // ================== RUN SIMULATION ==================
     
     // Schedule progress updates
     for (double t = 10.0; t < simTime; t += 10.0)
     {
         Simulator::Schedule(Seconds(t), [t, simTime]() {
             std::cout << "Simulation Progress: " << t 
                       << "/" << simTime << " seconds" << std::endl;
         });
     }
     
     std::cout << "\nStarting V2I simulation..." << std::endl;
     std::cout << "Vehicles sending data to base station..." << std::endl;
     
     Simulator::Stop(Seconds(simTime + 1));
     Simulator::Run();
     
     // ================== COLLECT STATISTICS ==================
     
     // Get total bytes received at base station
     Ptr<PacketSink> sink = DynamicCast<PacketSink>(baseStationApp.Get(0));
     uint32_t totalBytesReceived = sink->GetTotalRx();
     
     // Flow monitor statistics
     monitor->CheckForLostPackets();
     Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());
     FlowMonitor::FlowStatsContainer stats = monitor->GetFlowStats();
     
     // ================== PRINT RESULTS ==================
     
     std::cout << "\n========================================" << std::endl;
     std::cout << "         SIMULATION RESULTS" << std::endl;
     std::cout << "========================================" << std::endl;
     
     // Base station statistics
     std::cout << "\n--- BASE STATION STATISTICS ---" << std::endl;
     std::cout << "Total Data Received: " << totalBytesReceived / 1024.0 << " KB" << std::endl;
     std::cout << "Total Data Received: " << totalBytesReceived / (1024.0 * 1024.0) << " MB" << std::endl;
     std::cout << "Average Throughput: " << (totalBytesReceived * 8.0) / (simTime * 1000000.0) 
               << " Mbps" << std::endl;
     
     // Per-vehicle flow statistics
     std::cout << "\n--- PER-VEHICLE STATISTICS ---" << std::endl;
     
     uint32_t totalTxPackets = 0;
     uint32_t totalRxPackets = 0;
     double totalDelay = 0.0;
     uint32_t totalDelayPackets = 0;
     
     for (uint32_t i = 0; i < vehicles.GetN(); ++i)
     {
         Ipv4Address vehicleAddr = interfaces.GetAddress(i);
         
         // Find flows from this vehicle to base station
         for (auto const& flow : stats)
         {
             Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(flow.first);
             
             if (t.sourceAddress == vehicleAddr && t.destinationAddress == baseStationAddr)
             {
                 std::cout << "\nVehicle " << i << " (" << vehicleAddr << "):" << std::endl;
                 std::cout << "  TX Packets: " << flow.second.txPackets << std::endl;
                 std::cout << "  RX Packets: " << flow.second.rxPackets << std::endl;
                 std::cout << "  TX Bytes: " << flow.second.txBytes << std::endl;
                 std::cout << "  RX Bytes: " << flow.second.rxBytes << std::endl;
                 
                 if (flow.second.txPackets > 0)
                 {
                     double pdr = (flow.second.rxPackets * 100.0) / flow.second.txPackets;
                     std::cout << "  Delivery Ratio: " << pdr << "%" << std::endl;
                 }
                 
                 if (flow.second.rxPackets > 0)
                 {
                     double avgDelay = flow.second.delaySum.GetMilliSeconds() / flow.second.rxPackets;
                     std::cout << "  Avg Delay: " << avgDelay << " ms" << std::endl;
                     totalDelay += flow.second.delaySum.GetMilliSeconds();
                     totalDelayPackets += flow.second.rxPackets;
                 }
                 
                 double throughput = flow.second.rxBytes * 8.0 / simTime / 1000.0;  // kbps
                 std::cout << "  Throughput: " << throughput << " kbps" << std::endl;
                 
                 totalTxPackets += flow.second.txPackets;
                 totalRxPackets += flow.second.rxPackets;
                 
                 break;  // Found the flow for this vehicle
             }
         }
     }
     
     // Overall statistics
     std::cout << "\n--- OVERALL STATISTICS ---" << std::endl;
     std::cout << "Total TX Packets (all vehicles): " << totalTxPackets << std::endl;
     std::cout << "Total RX Packets (at base station): " << totalRxPackets << std::endl;
     
     if (totalTxPackets > 0)
     {
         std::cout << "Overall Packet Delivery Ratio: " 
                   << (totalRxPackets * 100.0) / totalTxPackets << "%" << std::endl;
     }
     
     if (totalDelayPackets > 0)
     {
         std::cout << "Average End-to-End Delay: " 
                   << totalDelay / totalDelayPackets << " ms" << std::endl;
     }
     
     std::cout << "\n========================================" << std::endl;
     std::cout << "    Simulation Completed Successfully!" << std::endl;
     std::cout << "========================================" << std::endl;
     
     // Cleanup
     Simulator::Destroy();
     
     return 0;
 }