
#ifndef AUTHENTICATED_STREAM_HPP
#define AUTHENTICATED_STREAM_HPP

#include "TorStream.hpp"
#include "../crypto/ed25519.h"
#include "../Constants.hpp"
#include <memory>
#include <chrono>

class AuthenticatedStream : public TorStream
{
 public:
  AuthenticatedStream(const std::string&,
                      ushort,
                      const std::string&,
                      ushort,
                      const ED_KEY&);
  Json::Value sendReceive(const std::string&, const std::string&);

 private:
  ED_KEY publicKey_;
  ED_SIGNATURE rootSig_;
  int lastTimestamp_;
};

#endif
