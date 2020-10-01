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
  std::string client_keylog, server_keylog;
  std::string client_keys, server_keys;

  bool DoCorrupt(Ptr<Packet> p);
  void DoReset(void);
  bool CheckForKeys(void);
};

#endif /* FAULTY_IMPLEMENTATION_ERROR_MODEL_H */
