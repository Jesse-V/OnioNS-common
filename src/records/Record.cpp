
#include "Record.hpp"
#include "../Utils.hpp"
#include "../Log.hpp"
#include "cppcodec/cppcodec/base32_default_rfc4648.hpp"
#include <botan/pubkey.h>
#include <botan/sha160.h>
#include <botan/sha2_32.h>
#include <botan/base64.h>
#include <chrono>
#include <random>


Record::Record(const std::shared_ptr<Botan::RSA_PrivateKey>& key)
    : privateKey_(key), publicKey_(key)
{
  memset(signature_.data(), 0, Const::RSA_SIGNATURE_LEN);
}



Record::Record(const Json::Value& json)  // reciprocal of asJSON
{
  privateKey_ = nullptr;

  if (json.isMember("type"))
    setType(json["type"].asString());

  if (json.isMember("name"))
    setName(json["name"].asString());

  if (json.isMember("contact"))
    setName(json["contact"].asString());

  StringMap subdomains;
  if (json.isMember("subd"))
  {
    Json::Value list = json["subd"];
    auto members = list.getMemberNames();
    for (auto item : members)
      subdomains.push_back(std::make_pair(item, list[item].asString()));
  }
  setSubdomains(subdomains);

  if (json.isMember("pubHSKey"))
    publicKey_ = Utils::BER64toRSA(json["pubHSKey"].asString());

  if (json.isMember("signature"))
    signature_ = Utils::decodeSignature(json["signature"].asString());
}



// ************************** ACTION METHODS ************************** //



std::string Record::resolve(const std::string& source) const
{
  // check TLD?

  if (source == name_)
  {
    if (secondaryAddrs_.empty())
      return computeOnion();
    else
    {
      // perform randomized load balancing between main and secondary addresses
      std::mt19937 rng(
          std::chrono::system_clock::now().time_since_epoch().count());
      auto value = rng() % (secondaryAddrs_.size() + 1);
      if (value == 0)
        return computeOnion();
      else
        return secondaryAddrs_[value - 1];
    }
  }

  // check subdomains
  for (auto sub : subdomains_)
    if (source == sub.first + "." + name_)
      return sub.second + "." + name_;

  // return empty string on failure
  return "";
}



// used just for the PoW check
SHA256_HASH Record::computeValue() const
{  // should we also hash the beacon and the public key?

  // sign();
  Botan::SHA_256 sha;
  auto hashBytes = sha.process(signature_.data(), Const::RSA_SIGNATURE_LEN);

  SHA256_HASH hashArray;
  std::copy(hashBytes.begin(), hashBytes.end(), hashArray.begin());
  return hashArray;
}



bool Record::computeValidity() const
{
  // thanks to the PoPETS reviewer who suggested checking PoW first to avoid DoS

  // compute PoW value
  SHA256_HASH hash = computeValue();
  for (int j = 0; j < Const::POW_THRESHOLD_BYTES; j++)  // check bytes
    if (hash.data()[j] != 0)
      return false;

  if (hash.data()[Const::POW_THRESHOLD_BYTES] > Const::POW_THRESHOLD)
    return false;

  Log::get().notice("Record has valid PoW value.");
  return verifySignature() && verifyStrings() && verifySubdomains() &&
         verifySecondaryAddrs() && verifyKeys();
}



bool Record::verifyStrings() const
{
  if (type_ != "record" && type_ != "ticket")
  {
    Log::get().warn("Record has unknown type: " + type_);
    return false;
  }

  if (name_.length() < 4 || name_.length() > 68)  // [4, 64 + 4]
  {
    Log::get().warn("Record has invalid name length. Must be in [4,68]");
    return false;
  }

  if (Utils::strEndsWith(name_, ".tor"))
  {
    Log::get().warn("Record name does not end in \".tor\"");
    return false;
  }

  if (contact_.size() > 40)
  {
    Log::get().warn("Record PGP fingerprint cannot exceed 40 bytes.");
    return false;
  }

  return true;
}



bool Record::verifySubdomains() const
{
  if (subdomains_.size() > 32)
  {
    Log::get().warn("Record has more than 32 subdomains.");
    return false;
  }

  for (auto pair : subdomains_)
  {
    if (pair.first.length() == 0 || pair.first.length() > 64)
    {
      Log::get().warn("Record has invalid length of subdomain name.");
      return false;
    }

    if (pair.second.length() == 0 || pair.second.length() > 64)
    {
      Log::get().warn("Record has invalid length of subdomain destination.");
      return false;
    }

    if (Utils::strEndsWith(pair.first, name_))
    {
      Log::get().warn("Record's subdomain contains its name.");
      return false;
    }

    if (!Utils::strEndsWith(pair.second, ".tor") &&
        !Utils::strEndsWith(pair.second, ".onion"))
    {
      Log::get().warn("Record's subdomain points outside Tor.");
      return false;
    }
  }

  return true;
}



bool Record::verifySignature() const
{
  // assemble data
  Json::FastWriter writer;
  Json::Value json = asJSON();
  json.removeMember("signature");
  std::string jsonStr = writer.write(json);

  // check signature
  auto bytes = reinterpret_cast<const unsigned char*>(jsonStr.data());
  Botan::PK_Verifier verifier(*publicKey_, "EMSA4(SHA-512)");
  if (!verifier.verify_message(bytes, jsonStr.size(), signature_.data(),
                               Const::RSA_SIGNATURE_LEN))
  {
    Log::get().warn("Record's signature is not valid.");
    return false;
  }

  return true;
}



bool Record::verifySecondaryAddrs() const
{
  if (secondaryAddrs_.size() > 7)
  {
    Log::get().warn("Record has more than 8 addresses.");
    return false;
  }

  for (auto addr : secondaryAddrs_)
  {
    if (addr.length() != 16 + 6)
    {
      Log::get().warn("Record's secondary address has invalid length.");
      return false;
    }

    if (!Utils::strEndsWith(addr, ".onion"))
    {
      Log::get().warn("Record's secondary address does not end in \".onion\"");
      return false;
    }
  }

  return true;
}



bool Record::verifyKeys() const
{
  if (!privateKey_ && !publicKey_)  // need at least one key
    return false;

  // check private key
  auto size = privateKey_->get_n().bits();
  if (privateKey_ && size != Const::RSA_LEN)
  {
    Log::get().warn("Record has " + std::to_string(size) +
                    "-bit private key. Expected 1024-bit RSA.");
    return false;
  }

  // check public key
  size = publicKey_->get_n().bits();
  if (publicKey_ && size != Const::RSA_LEN)
  {
    Log::get().warn("Record has " + std::to_string(size) +
                    "-bit public key. Expected 1024-bit RSA.");
    return false;
  }

  return true;
}



// used to uniquely identify the record
SHA256_HASH Record::hash() const
{  // hashing the JSON is slower, but improves flexibility and helps -HS code

  Json::FastWriter writer;
  std::string str = writer.write(asJSON());

  Botan::SHA_256 sha;
  SHA256_HASH hashBytes;
  auto shaHash = sha.process(str);
  std::copy(shaHash.begin(), shaHash.end(), hashBytes.begin());
  return hashBytes;
}



void Record::sign()
{
  static Botan::AutoSeeded_RNG rng;

  Json::FastWriter writer;
  Json::Value json = asJSON();
  json.removeMember("signature");
  std::string jsonStr = writer.write(json);

  auto bytes = reinterpret_cast<const unsigned char*>(jsonStr.data());
  Botan::PK_Signer signer(*privateKey_, "EMSA4(SHA-512)");
  auto sig = signer.sign_message(bytes, jsonStr.size(), rng);
  std::copy(sig.begin(), sig.end(), signature_.begin());
}



std::string Record::computeOnion() const
{
  // https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt :
  // When we refer to "the hash of a public key", we mean the SHA-1 hash of the
  // DER encoding of an ASN.1 RSA public key (as specified in PKCS.1).

  // get DER encoding of RSA key
  std::string keyBinStr;
  auto x509Key = privateKey_->x509_subject_public_key();
  std::copy(x509Key.begin(), x509Key.end(), keyBinStr.begin());

  // perform SHA-1
  std::string hashBin;
  Botan::SHA_160 sha1;
  auto hash = sha1.process(keyBinStr);
  std::copy(hash.begin(), hash.end(), hashBin.begin());

  // encode, make lowercase, truncate, and return
  auto oAddr = base32::encode(hashBin);
  std::transform(oAddr.begin(), oAddr.end(), oAddr.begin(), ::tolower);
  return std::string(oAddr, 16) + ".onion";
}



Json::Value Record::asJSON() const
{
  Json::Value obj;

  obj["type"] = type_;
  obj["name"] = name_;
  if (!contact_.empty())
    obj["contact"] = contact_;

  // add subdomains, if they exist
  for (auto sub : subdomains_)
    obj["subd"][sub.first] = sub.second;

  // extract and save public key
  auto ber = getPublicKeyBER();
  obj["pubHSKey"] = Botan::base64_encode(ber.data, ber.length);
  obj["signature"] = Botan::base64_encode(signature_.data(), signature_.size());
  return obj;
}



std::ostream& operator<<(std::ostream& os, const Record& r)
{
  bool valid = r.computeValidity();
  std::string onion = r.computeOnion();

  os << "Domain Registration: (currently " << (valid ? "VALID)" : "INVALID)")
     << std::endl;

  os << "   Domain Information: " << std::endl;
  os << "      " << r.name_ << " -> " << onion << std::endl;

  for (auto addr : r.secondaryAddrs_)
    os << "      " << addr << " -> " << onion << std::endl;

  for (auto subd : r.subdomains_)
    os << "      " << subd.first << "." << r.name_ << " -> " << subd.second
       << std::endl;

  if (r.contact_.empty())
    os << "   Contact: PGP 0x" << r.contact_ << std::endl;
  os << "   Validation:" << std::endl;

  os << "      Proof of Work: ";
  if (valid)
    os << "Below threshold" << std::endl;
  else
    os << "<regeneration required>" << std::endl;

  os << "      Signature: ";
  if (valid)
    os << Botan::base64_encode(r.signature_.data(), r.signature_.size() / 4)
       << " ..." << std::endl;
  else
    os << "<regeneration required>" << std::endl;

  auto pem = Botan::X509::PEM_encode(*r.publicKey_);
  pem.pop_back();  // delete trailing /n
  Utils::stringReplace(pem, "\n", "\n\t");
  os << "      RSA Public Key: \n\t" << pem;

  return os;
}


// ************************** SET METHODS ************************** //



void Record::setType(const std::string& type)
{
  type_ = type;
}


void Record::setName(const std::string& name)
{
  name_ = name;
}



void Record::setContact(const std::string& contact)
{
  contact_ = contact;
}



void Record::setSubdomains(const StringMap& subdomains)
{
  subdomains_ = subdomains;
}



void Record::setSecondaryAddresses(const std::vector<std::string>& addrs)
{
  secondaryAddrs_ = addrs;
}



void Record::setPrivateKey(const std::shared_ptr<Botan::RSA_PrivateKey>& key)
{
  privateKey_ = key;
}



// ************************** GET METHODS ************************** //



std::string Record::getType() const
{
  return type_;
}



std::string Record::getName() const
{
  return name_;
}



std::string Record::getContact() const
{
  return contact_;
}



StringMap Record::getSubdomains() const
{
  return subdomains_;
}



std::vector<std::string> Record::getSecondaryAddresses() const
{
  return secondaryAddrs_;
}



std::shared_ptr<Botan::RSA_PublicKey> Record::getPublicKey() const
{
  return privateKey_;
}



// https://en.wikipedia.org/wiki/X.690#BER_encoding
UInt8Array Record::getPublicKeyBER() const
{
  std::string berBin;
  auto ber = Botan::X509::BER_encode(*getPublicKey());
  std::copy(ber.begin(), ber.end(), berBin.begin());

  UInt8Array array;
  array.data = reinterpret_cast<const unsigned char*>(berBin.data());
  array.length = ber.size();
  Log::get().notice("BER size: " + std::to_string(ber.size()));
  return array;
}



RSA_SIGNATURE Record::getSignature() const
{
  return signature_;
}
