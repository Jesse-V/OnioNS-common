
#include "AuthenticatedStream.hpp"
#include "../Log.hpp"


AuthenticatedStream::AuthenticatedStream(const std::string& socksHost,
                                         ushort socksPort,
                                         const std::string& remoteHost,
                                         ushort remotePort,
                                         const ED_KEY& publicKey)
    : TorStream(socksHost, socksPort, remoteHost, remotePort),
      publicKey_(publicKey)
{
  rootSig_.fill(0);
}



Json::Value AuthenticatedStream::sendReceive(const std::string& type,
                                             const std::string& msg)
{
  Log::get().notice("AuthStream sendReceive called");

  Json::Value received = TorStream::sendReceive(type, msg);

  if (!received.isMember("signature"))
  {
    received["type"] = "error";
    received["value"] = "Missing signature from server.";
  }

  // if the error happened above or any other existing error happened
  if (received["type"].asString() == "error")
    return received;

  std::string data = received["type"].asString() + received["value"].asString();

  const uint8_t* bytes = reinterpret_cast<const uint8_t*>(data.c_str());
  const uint8_t* signature = reinterpret_cast<const uint8_t*>(
      received["signature"].asString().c_str());

  // check signature on transmission
  int check =
      ed25519_sign_open(bytes, data.size(), publicKey_.data(), signature);
  if (check == 1)
  {
    received["type"] = "error";
    received["value"] = "Bad Ed25519 signature from server.";
  }
  else if (check == -1)
  {
    received["type"] = "error";
    received["value"] = "General Ed25519 failure on transmission signature.";
  }

  return received;
}
