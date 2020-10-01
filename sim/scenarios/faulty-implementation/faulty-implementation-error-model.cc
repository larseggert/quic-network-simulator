#include <cassert>
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

#include "ns3/core-module.h"
#include "ns3/header.h"
#include "ns3/ipv4-header.h"
#include "ns3/packet.h"
#include "ns3/ppp-header.h"
#include "ns3/udp-header.h"

#include "../helper/openssl-helper.h"
#include "../helper/quic-packet.h"

#include "faulty-implementation-error-model.h"
#include "hexdump.h"

using namespace std;

NS_OBJECT_ENSURE_REGISTERED(FaultyImplementationErrorModel);

TypeId FaultyImplementationErrorModel::GetTypeId(void) {
  static TypeId tid = TypeId("FaultyImplementationErrorModel")
                          .SetParent<ErrorModel>()
                          .AddConstructor<FaultyImplementationErrorModel>();
  return tid;
}

FaultyImplementationErrorModel::FaultyImplementationErrorModel()
    : pct(0), distr(0, 99) {
  std::random_device rd;
  rng = new std::mt19937(rd());
}

void FaultyImplementationErrorModel::DoReset(void) {}

void FaultyImplementationErrorModel::CheckForKeys() {
  if (keylog.length() > 0)
    return;

  std::ifstream my_ifs(my_keylog_file);
  if (my_ifs.good())
    keylog.assign((std::istreambuf_iterator<char>(my_ifs)),
                  (std::istreambuf_iterator<char>()));

  if (keylog.length() == 0) {
    std::ifstream peer_ifs(peer_keylog_file);
    if (peer_ifs.good())
      keylog.assign((std::istreambuf_iterator<char>(peer_ifs)),
                    (std::istreambuf_iterator<char>()));
  }

  if (keylog.length() > 0) {
    handshake_key_len =
        ParseKeylog(is_client ? "QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET"
                              : "QUIC_SERVER_HANDSHAKE_TRAFFIC_SECRET",
                    handshake_key, sizeof(handshake_key));
    data_key_len = ParseKeylog(is_client ? "QUIC_CLIENT_TRAFFIC_SECRET_0"
                                         : "QUIC_SERVER_TRAFFIC_SECRET_0",
                               data_key, sizeof(data_key));
  }
}

size_t FaultyImplementationErrorModel::ParseKeylog(const string tag,
                                                   uint8_t *const key,
                                                   const size_t len) {

  // find tag
  const size_t pos_tag = keylog.find(tag);
  if (pos_tag != string::npos) {
    // ignore CID, assume only one connection exists
    const size_t pos_cid = keylog.find(" ", pos_tag);
    if (pos_cid != string::npos) {
      const size_t pos_key = keylog.find(" ", pos_cid + 1);
      if (pos_key != string::npos) {
        const size_t pos_eol = keylog.find("\n", pos_key + 1);
        if (pos_eol != string::npos) {
          const size_t l = pos_eol - pos_key - 1;
          assert(l <= len * 2);
          const string keystr = keylog.substr(pos_key + 1, l);
          cout << tag << ": " << keystr << endl;
          size_t pos = 0;
          bool lo = false;
          for (uint8_t c : keystr) {
            assert(pos < len);
            const uint8_t x =
                c <= '9' ? c - '0' : (c <= 'F' ? c - 'A' + 10 : c - 'a' + 10);
            if (lo == false)
              key[pos] = x << 4;
            else
              key[pos++] |= x;
            pos++;
            lo = !lo;
          }
          return pos;
        }
      }
    }
  }
  keylog.empty();
  return 0;
}

bool FaultyImplementationErrorModel::DoCorrupt(Ptr<Packet> p) {
  if (pct == 0)
    return false;

  if (keylog.length() == 0)
    CheckForKeys();

  QuicPacket qp = QuicPacket(p);
  const size_t corrupt_cnt = qp.GetUdpPayload().size() / pct;

  cout << Simulator::Now().GetSeconds() << "s: ";

  if (qp.IsVersionNegotiationPacket() || corrupt_cnt == 0) {
    cout << "forwarding packet (" << qp.GetUdpPayload().size()
         << " bytes) from " << qp.GetIpv4Header().GetSource() << endl;
    qp.ReassemblePacket();
    return false;
  }

  cout << corrupt_cnt << "/" << qp.GetUdpPayload().size()
       << " bytes to corrupt:" << endl;

  vector<uint8_t> &payload = qp.GetUdpPayload();
  cout << Hexdump(payload.data(), payload.size()) << std::endl;

  uint8_t plaintext[2048];
  const int plaintext_len = gcm_decrypt(
      payload.data(), payload.size(), nullptr /*unsigned char *aad*/,
      0 /*int aad_len*/, unsigned char *tag, unsigned char *key,
      unsigned char *iv, int iv_len, plaintext);

  cout << Hexdump(plaintext, plaintext_len) << std::endl;

  // if (distr(*rng) >= pct) {
  //   cout << "Forwarding packet (" << qp.GetUdpPayload().size()
  //        << " bytes) from " << qp.GetIpv4Header().GetSource() << endl;
  //   qp.ReassemblePacket();
  //   return false;
  // }

  // cout << "Corrupting packet (" << qp.GetUdpPayload().size() << " bytes) from
  // "
  //      << qp.GetIpv4Header().GetSource() << endl;

  // // Corrupt a byte in the 50 bytes of the UDP payload.
  // // This way, we will frequenetly hit the QUIC header.
  // std::uniform_int_distribution<> d(0, min(uint32_t(50), p->GetSize() - 1));
  // int pos = d(*rng);
  // vector<uint8_t> &payload = qp.GetUdpPayload();
  // // Replace the byte at position pos with a random value.
  // while (true) {
  //   uint8_t n = std::uniform_int_distribution<>(0, 255)(*rng);
  //   if (payload[pos] == n)
  //     continue;
  //   cout << "Corrupted packet (" << qp.GetUdpPayload().size() << " bytes)
  //   from "
  //        << qp.GetIpv4Header().GetSource() << " at offset " << pos << " (0x"
  //        << std::hex << (unsigned int)payload[pos] << " -> 0x"
  //        << (unsigned int)n << ")" << std::dec << endl;
  //   payload[pos] = n;
  //   break;
  // }

  qp.ReassemblePacket();
  return false;
}

void FaultyImplementationErrorModel::SetByteErrorRate(int ber) { pct = ber; }

void FaultyImplementationErrorModel::SetKeylogs(const std::string &my,
                                                const std::string &peer) {
  my_keylog_file = my;
  peer_keylog_file = peer;
}
