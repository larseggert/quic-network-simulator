#include <cassert>
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

#include <openssl/evp.h>

#include "ns3/core-module.h"
#include "ns3/header.h"
#include "ns3/ipv4-header.h"
#include "ns3/packet.h"
#include "ns3/ppp-header.h"
#include "ns3/udp-header.h"

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
#if 0
int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len, unsigned char *tag,
                unsigned char *key, unsigned char *iv, int iv_len,
                unsigned char *plaintext) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;
  int ret;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new()))
    assert(0);

  /* Initialise the decryption operation. */
  if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
    assert(0);

  /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
    assert(0);

  /* Initialise key and IV */
  if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
    assert(0);

  /*
   * Provide any AAD data. This can be called zero or more times as
   * required
   */
  if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
    assert(0);

  /*
   * Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    assert(0);
  plaintext_len = len;

  /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
    assert(0);

  /*
   * Finalise the decryption. A positive return value indicates success,
   * anything else is a failure - the plaintext is not trustworthy.
   */
  ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  if (ret > 0) {
    /* Success */
    plaintext_len += len;
    return plaintext_len;
  } else {
    /* Verify failed */
    return -1;
  }
}
#endif

bool FaultyImplementationErrorModel::CheckForKeys() {
  if (client_keys.length() > 0 || server_keys.length() > 0)
    return true;

  std::ifstream client_ifs(client_keylog);
  if (client_ifs.good())
    client_keys.assign((std::istreambuf_iterator<char>(client_ifs)),
                       (std::istreambuf_iterator<char>()));
  else {
    cout << "no " << client_keylog << endl;
    const int ret = system((string("ls -la ") + client_keylog).c_str());
    assert(ret != -1);

    std::ifstream server_ifs(server_keylog);
    if (server_ifs.good())
      server_keys.assign((std::istreambuf_iterator<char>(server_ifs)),
                         (std::istreambuf_iterator<char>()));
    else
      cout << "no " << server_keylog << endl;
  }

  return client_keys.length() > 0 || server_keys.length() > 0;
}

bool FaultyImplementationErrorModel::DoCorrupt(Ptr<Packet> p) {
  if (pct == 0)
    return false;

  if (CheckForKeys() == false)
    return false;

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

  // uint8_t plaintext[2048];
  // const int plaintext_len =
  //     gcm_decrypt(payload.data(), payload.size(), unsigned char *aad,
  //                 int aad_len, unsigned char *tag, unsigned char *key,
  //                 unsigned char *iv, int iv_len, plaintext);

  // cout << Hexdump(plaintext, plaintext_len) << std::endl;

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

void FaultyImplementationErrorModel::SetKeylogs(const std::string &client,
                                                const std::string &server) {
  client_keylog = client;
  server_keylog = server;
}
