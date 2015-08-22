
#include "Common.hpp"
#include "containers/records/CreateR.hpp"
#include "Utils.hpp"
#include "Log.hpp"
#include <botan/sha2_64.h>
#include <fstream>


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



// ************************** PRIVATE METHODS ****************************** //



RecordPtr Common::assembleRecord(const Json::Value& rVal)
{
  auto contact = rVal["contact"].asString();
  auto nonce = rVal["nonce"].asString();
  auto pow = rVal["pow"].asString();
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
  return std::make_shared<CreateR>(contact, name, subdomains, nonce, pow, sig,
                                   key);
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
