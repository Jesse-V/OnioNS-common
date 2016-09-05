
#include "Common.hpp"
#include "records/CreateR.hpp"
#include "Utils.hpp"
#include "Log.hpp"
//#include "ed25519-donna/ed25519.h"
//#include <botan/sha2_64.h>
//#include <botan/base64.h>
//#include <fstream>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>


RecordPtr Common::parseRecord(const std::string& json)
{
  return parseRecord(toJSON(json));
}



RecordPtr Common::parseRecord(const Json::Value& rVal)
{
  RecordPtr r = assembleRecord(rVal);
  checkValidity(r);
  return r;
}



Json::Value Common::toJSON(const std::string& json)
{
  Json::Value rVal;
  Json::Reader reader;

  if (!reader.parse(json, rVal))
    Log::get().error("Failed to parse Record!");

  return rVal;
}



std::string Common::getDestination(const RecordPtr& record,
                                   const std::string& source)
{
  if (record->getName() == source)
    return record->getOnion();

  NameList list = record->getSubdomains();
  for (auto subdomain : list)
    if (subdomain.first + "." + record->getName() == source)
      return subdomain.second;

  Log::get().error("Record does not contain \"" + source + "\"!");
  return "";
}


/*
// modifies sig in place
std::pair<bool, int> Common::verifyRootSignature(const Json::Value& sigObj,
                                                 ED_SIGNATURE& sig,
                                                 const SHA256_HASH& root,
                                                 const std::string& key)
{
  // sanity check
  if (!sigObj.isMember("signature") || !sigObj.isMember("count"))
  {
    Log::get().warn("Invalid root signature.");
    return std::make_pair(false, -1);
  }

  // decode signature
  if (Botan::base64_decode(sig.data(), sigObj["signature"].asString()) !=
      sig.size())
  {
    Log::get().warn("Invalid root signature length from Quorum node.");
    return std::make_pair(false, -1);
  }

  // decode public key
  ED_KEY qPubKey;
  if (Botan::base64_decode(qPubKey.data(), key) != Const::ED25519_KEY_LEN)
  {
    Log::get().warn("Quorum node key has an invalid length.");
    return std::make_pair(false, -1);
  }

  // check signature
  int status = ed25519_sign_open(root.data(), Const::SHA256_LEN, qPubKey.data(),
                                 sig.data());

  // announce results
  if (status == 0)
    Log::get().notice("Valid Ed25519 Quorum signature on root.");
  else if (status == 1)
    Log::get().warn("Invalid Ed25519 Quorum signature on root.");
  else
    Log::get().warn("General Ed25519 signature failure on root.");

  return std::make_pair(status == 0, sigObj["count"].asInt());
}
*/


// returns the full path of ~/.OnioNS or creates it if it doesn't exist
std::string Common::getWorkingDirectory()
{
  std::string workingDir(getpwuid(getuid())->pw_dir);
  workingDir += "/.OnioNS/";

  if (mkdir(workingDir.c_str(), 0750) == 0)
    Log::get().notice("Working directory successfully created.");

  return workingDir;
}



// ************************** PRIVATE METHODS ****************************** //



RecordPtr Common::assembleRecord(const Json::Value& rVal)
{
  auto contact = rVal["contact"].asString();
  auto nonce = rVal["nonce"].asString();
  auto pubHSKey = rVal["pubHSKey"].asString();
  auto sig = rVal["recordSig"].asString();
  auto type = rVal["type"].asString();
  auto name = rVal["name"].asString();

  if (type != "Create")
    Log::get().error("Record parsing: not a Create Record!");

  NameList subdomains;
  if (rVal.isMember("subd"))
  {
    Json::Value list = rVal["subd"];
    auto sources = list.getMemberNames();
    for (auto source : sources)
      subdomains.push_back(std::make_pair(source, list[source].asString()));
  }

  auto key = Utils::base64ToRSA(pubHSKey);
  return std::make_shared<CreateR>(contact, name, subdomains, nonce, sig, key);
}



void Common::checkValidity(const RecordPtr& r)
{
  Log::get().notice("Checking validity... ");

  bool tmp = false;
  r->computeValidity(&tmp);

  if (r->hasValidSignature())
    Log::get().notice("Record signature is valid.");
  else
    Log::get().error("Bad signature on Record!");

  if (r->isValid())  // todo: this does not actually check the PoW output
    Log::get().notice("Record proof-of-work is valid.");
  else
    Log::get().error("Record is not valid!");

  Log::get().notice("Record check complete.");
}
