/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

#include "ns3/abort.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/fd-net-device-module.h"
#include "ns3/internet-apps-module.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/ipv4-list-routing-helper.h"
#include "ns3/csma-module.h"
#include "ns3/point-to-point-module.h"


using namespace ns3;

NS_LOG_COMPONENT_DEFINE("ns3 simulator");

void installNetDevice(Ptr<Node> node, std::string deviceName, Mac48AddressValue macAddress, Ipv4InterfaceAddress ipv4Address) {
  EmuFdNetDeviceHelper emu;
  emu.SetDeviceName(deviceName);
  NetDeviceContainer devices = emu.Install(node);
  Ptr<NetDevice> device = devices.Get(0);
  device->SetAttribute("Address", macAddress);

  Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
  uint32_t interface = ipv4->AddInterface(device);
  ipv4->AddAddress(interface, ipv4Address);
  ipv4->SetMetric(interface, 1);
  ipv4->SetUp(interface);
}


int main(int argc, char *argv[]) {
  GlobalValue::Bind("SimulatorImplementationType", StringValue("ns3::RealtimeSimulatorImpl"));
  GlobalValue::Bind("ChecksumEnabled", BooleanValue(true));

  // The topology has a CSMA network of 4 nodes on the left side.
  NodeContainer nodesLeft;
  nodesLeft.Create(4);

  CsmaHelper csmaLeft;
  csmaLeft.SetChannelAttribute("DataRate", DataRateValue (5000000));
  csmaLeft.SetChannelAttribute("Delay", TimeValue (MilliSeconds (1)));

  NetDeviceContainer devicesLeft = csmaLeft.Install(nodesLeft);
  InternetStackHelper internetLeft;
  internetLeft.Install(nodesLeft);

  Ipv4AddressHelper ipv4Left;
  ipv4Left.SetBase("10.1.0.0", "255.255.0.0", "0.0.0.10");
  Ipv4InterfaceContainer interfacesLeft = ipv4Left.Assign(devicesLeft);

  // Create the right side CSMA network of 4 nodes.
  NodeContainer nodesRight;
  nodesRight.Create(4);

  CsmaHelper csmaRight;
  csmaRight.SetChannelAttribute("DataRate", DataRateValue(5000000));
  csmaRight.SetChannelAttribute("Delay", TimeValue(MilliSeconds(1)));

  NetDeviceContainer devicesRight = csmaRight.Install(nodesRight);

  InternetStackHelper internetRight;
  internetRight.Install(nodesRight);
  
  Ipv4AddressHelper ipv4Right;
  ipv4Right.SetBase("10.99.0.0", "255.255.0.0", "0.0.0.10");
  Ipv4InterfaceContainer interfacesRight = ipv4Right.Assign(devicesRight);

  // Stick in the point-to-point line between the sides.
  PointToPointHelper p2p;
  p2p.SetDeviceAttribute("DataRate", StringValue("512Mbps"));
  p2p.SetChannelAttribute("Delay", StringValue("10ms"));

  NodeContainer nodes = NodeContainer(nodesLeft.Get(3), nodesRight.Get(3));
  NetDeviceContainer devices = p2p.Install(nodes);

  Ipv4AddressHelper ipv4;
  ipv4.SetBase("10.50.0.0", "255.255.0.0");
  Ipv4InterfaceContainer interfaces = ipv4.Assign(devices);

  NS_LOG_INFO("Create eth0");
  installNetDevice(nodesLeft.Get(0), "eth0", Mac48AddressValue("02:51:55:49:43:00"), Ipv4InterfaceAddress("10.0.0.2", "255.255.0.0"));
  NS_LOG_INFO("Create eth1");
  installNetDevice(nodesRight.Get(0), "eth1", Mac48AddressValue("02:51:55:49:43:01"), Ipv4InterfaceAddress("10.100.0.2", "255.255.0.0"));

  // enable pcaps for all nodes
  csmaLeft.EnablePcapAll("tap-wifi-dumbbell", false);
  csmaRight.EnablePcapAll("tap-wifi-dumbbell", false);

  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

  // write the routing table to file
  Ptr<OutputStreamWrapper> routingStream = Create<OutputStreamWrapper>("dynamic-global-routing.routes", std::ios::out);
  Ipv4RoutingHelper::PrintRoutingTableAllAt(Seconds(0.), routingStream);

  NS_LOG_INFO("Run Emulation.");
  Simulator::Stop(Seconds(36000.0));
  Simulator::Run();
  Simulator::Destroy();
  NS_LOG_INFO("Done.");
}
