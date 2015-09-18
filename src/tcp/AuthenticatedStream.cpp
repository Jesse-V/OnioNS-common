
#include "AuthenticatedStream.hpp"
#include "../Log.hpp"


AuthenticatedStream::AuthenticatedStream(const std::string& socksHost,
                                         ushort socksPort,
                                         const std::string& remoteHost,
                                         ushort remotePort,
                                         const ED_KEY& publicKey)
    : TorStream(socksHost, socksPort, remoteHost, remotePort),
      publicKey_(publicKey),
      lastTimestamp_(0)
{
  rootSig_.fill(0);
}



Json::Value AuthenticatedStream::sendReceive(const std::string& type,
                                             const std::string& msg)
{
  Json::Value received = TorStream::sendReceive(type, msg);

  std::string data = received["type"].asString() +
                     received["value"].asString() + received["time"].asString();

  const uint8_t* bytes = reinterpret_cast<const uint8_t*>(data.c_str());
  const uint8_t* signature = reinterpret_cast<const uint8_t*>(
      received["signature"].asString().c_str());

  // todo: check Merkle root signature, here?

  // check signature on transmission
  int check =
      ed25519_sign_open(bytes, data.size(), publicKey_.data(), signature);
  if (check == 1)
    Log::get().warn("Bad Ed25519 signature from server.");
  else
    Log::get().error("General Ed25519 failure on transmission signature");

  // check timestamp
  auto receivedTime = received["time"].asInt();
  auto myTime =
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch()).count();

  if (lastTimestamp_ != 0 && std::abs(receivedTime - myTime) > 600000)
    Log::get().warn("Clocks differ > 10 mins, cannot guarentee liveliness.");

  if (receivedTime < lastTimestamp_)
    Log::get().warn("Unexpected server timestamp, possible replay attack.");

  lastTimestamp_ = receivedTime;

  return received;
}
