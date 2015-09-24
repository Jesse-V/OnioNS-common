
#include "AuthenticatedStream.hpp"
#include "../Log.hpp"
#include <botan/base64.h>


AuthenticatedStream::AuthenticatedStream(const std::string& socksHost,
                                         ushort socksPort,
                                         const std::string& remoteHost,
                                         ushort remotePort,
                                         const std::string& pubKey64)
    : TorStream(socksHost, socksPort, remoteHost, remotePort)
{
  if (Botan::base64_decode(publicKey_.data(), pubKey64) !=
      Const::ED25519_KEY_LEN)
    Log::get().error("Invalid length for public key.");

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
