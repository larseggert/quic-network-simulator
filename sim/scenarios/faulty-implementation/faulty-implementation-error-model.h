#ifndef FAULTY_IMPLEMENTATION_ERROR_MODEL_H
#define FAULTY_IMPLEMENTATION_ERROR_MODEL_H

#include <random>

#include "ns3/error-model.h"

using namespace ns3;

class FaultyImplementationErrorModel : public RateErrorModel {
public:
  static TypeId GetTypeId(void);
  FaultyImplementationErrorModel();
  void SetByteErrorRate(int ber);
  void SetKeylogs(const std::string &client, const std::string &server);

private:
  int pct;
  std::mt19937 *rng;
  std::uniform_int_distribution<> distr;
  std::string my_keylog_file, peer_keylog_file;
  std::string keylog;
  uint8_t handshake_key[64], data_key[64];
  uint8_t handshake_key_len, data_key_len;
  bool is_client;

  bool DoCorrupt(Ptr<Packet> p);
  void DoReset(void);
  void CheckForKeys(void);
  size_t ParseKeylog(const std::string tag, uint8_t *const key,
                     const size_t len);
};

#endif /* FAULTY_IMPLEMENTATION_ERROR_MODEL_H */
