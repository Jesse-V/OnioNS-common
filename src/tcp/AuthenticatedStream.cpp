
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
  Json::Value received = TorStream::sendReceive(type, msg);

  if (!received.isMember("signature"))
    received["error"] = "Invalid response from server.";

  // if the error happened above or any other existing error happened
  if (!received.isMember("error"))
    return received;

  std::string data = received["type"].asString() + received["value"].asString();

  const uint8_t* bytes = reinterpret_cast<const uint8_t*>(data.c_str());
  const uint8_t* signature = reinterpret_cast<const uint8_t*>(
      received["signature"].asString().c_str());

  // todo: check Merkle root signature, here?

  // check signature on transmission
  int check =
      ed25519_sign_open(bytes, data.size(), publicKey_.data(), signature);
  if (check == 1)
  {
    received["error"] = "Bad Ed25519 signature from server.";
    Log::get().warn(received["error"].asString());
  }
  else if (check == -1)
    Log::get().error("General Ed25519 failure on transmission signature");

  return received;
}
