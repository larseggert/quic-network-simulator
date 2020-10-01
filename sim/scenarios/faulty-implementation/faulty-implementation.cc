#include "ns3/core-module.h"
#include "ns3/error-model.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/string.h"

#include "../helper/quic-network-simulator-helper.h"
#include "../helper/quic-point-to-point-helper.h"

#include "faulty-implementation-error-model.h"

using namespace ns3;
using namespace std;

NS_LOG_COMPONENT_DEFINE("ns3 simulator");

int main(int argc, char *argv[]) {
  string delay, bandwidth, queue, client_ber, server_ber, client_keylog,
      server_keylog;
  random_device rand_dev;
  mt19937 generator(rand_dev()); // Seed random number generator first
  Ptr<FaultyImplementationErrorModel> client_em =
      CreateObject<FaultyImplementationErrorModel>();
  Ptr<FaultyImplementationErrorModel> server_em =
      CreateObject<FaultyImplementationErrorModel>();
  CommandLine cmd;

  cmd.AddValue("delay", "delay of the p2p link", delay);
  cmd.AddValue("bandwidth", "bandwidth of the p2p link", bandwidth);
  cmd.AddValue("queue", "queue size of the p2p link (in packets)", queue);
  cmd.AddValue("ber-client", "byte-error rate (from client)", client_ber);
  cmd.AddValue("ber-server", "byte-error rate (from server)", server_ber);
  cmd.AddValue("client_keylog", "client SSLKEYLOGFILE path", client_keylog);
  cmd.AddValue("server_keylog", "server SSLKEYLOGFILE path", server_keylog);
  cmd.Parse(argc, argv);

  NS_ABORT_MSG_IF(delay.length() == 0, "Missing parameter: delay");
  NS_ABORT_MSG_IF(bandwidth.length() == 0, "Missing parameter: bandwidth");
  NS_ABORT_MSG_IF(queue.length() == 0, "Missing parameter: queue");
  NS_ABORT_MSG_IF(client_ber.length() == 0, "Missing parameter: ber-client");
  NS_ABORT_MSG_IF(server_ber.length() == 0, "Missing parameter: ber-server");
  NS_ABORT_MSG_IF(client_keylog.length() == 0,
                  "Missing parameter: client_keylog");
  NS_ABORT_MSG_IF(server_keylog.length() == 0,
                  "Missing parameter: server_keylog");

  client_em->SetByteErrorRate(stoi(client_ber));
  server_em->SetByteErrorRate(stoi(server_ber));
  client_em->SetKeylogs(client_keylog, server_keylog);
  server_em->SetKeylogs(server_keylog, client_keylog);

  QuicNetworkSimulatorHelper sim;

  // Stick in the point-to-point line between the sides.
  QuicPointToPointHelper p2p;
  p2p.SetDeviceAttribute("DataRate", StringValue(bandwidth));
  p2p.SetChannelAttribute("Delay", StringValue(delay));
  p2p.SetQueueSize(StringValue(queue + "p"));

  NetDeviceContainer devices =
      p2p.Install(sim.GetLeftNode(), sim.GetRightNode());
  Ipv4AddressHelper ipv4;
  ipv4.SetBase("193.167.50.0", "255.255.255.0");
  Ipv4InterfaceContainer interfaces = ipv4.Assign(devices);

  devices.Get(0)->SetAttribute("ReceiveErrorModel", PointerValue(server_em));
  devices.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(client_em));

  sim.Run(Seconds(36000));
}
