
#include "Record.hpp"
#include "../Log.hpp"
#include "../Utils.hpp"
#include "cppcodec/cppcodec/base32_default_rfc4648.hpp"
#include <botan/pubkey.h>
#include <botan/sha2_32.h>
#include <botan/sha160.h>
#include <botan/base64.h>
#include <sstream>
#include <cmath>


Record::Record(const Json::Value& json)  // reciprocal of asJSON
{
  Log::get().debug("Decoding JSON into Record...");

  // zero variables by default
  edKey_.fill(0);
  edSig_.fill(0);
  serviceSig_.fill(0);
  serviceKey_ = nullptr;
  nonce_ = rng_ = 0;

  if (json.isMember("edKey"))
  {
    auto bytes =
        Utils::decodeBase64(json["edKey"].asString(), Const::EdDSA_KEY_LEN);
    std::copy(bytes.begin(), bytes.end(), edKey_.begin());
  }

  if (json.isMember("edSig"))
  {
    auto bytes =
        Utils::decodeBase64(json["edSig"].asString(), Const::EdDSA_SIG_LEN);
    std::copy(bytes.begin(), bytes.end(), edSig_.begin());
  }

  if (json.isMember("rsaKey"))
  {
    auto bin =
        Utils::decodeBase64(json["rsaKey"].asString(), Const::RSA_KEY_LEN);
    if (!bin.empty())
    {
      // interpret and parse into public RSA key
      std::string str(reinterpret_cast<const char*>(bin.data()), bin.size());
      std::istringstream iss(str);
      Botan::DataSource_Stream keyStream(iss);
      setServicePublicKey(std::make_shared<Botan::RSA_PublicKey>(
          *dynamic_cast<Botan::RSA_PublicKey*>(
              Botan::X509::load_key(keyStream))));
    }
  }

  if (json.isMember("rsaSig"))
  {
    auto bytes =
        Utils::decodeBase64(json["rsaSig"].asString(), Const::RSA_SIG_LEN);
    std::copy(bytes.begin(), bytes.end(), serviceSig_.begin());
  }

  Log::get().debug("Finished decoding keys and signatures.");

  if (json.isMember("type"))
    setType(json["type"].asString());

  if (json.isMember("name"))
    setName(json["name"].asString());

  if (json.isMember("pgp"))
    setName(json["pgp"].asString());

  StringMap subdomains;
  if (json.isMember("subd"))
  {
    Json::Value list = json["subd"];
    auto members = list.getMemberNames();
    for (auto item : members)
      subdomains.push_back(std::make_pair(item, list[item].asString()));
  }
  setSubdomains(subdomains);

  if (json.isMember("rng") && json["rng"].isUInt())
    setRNG(json["rng"].asUInt());

  if (json.isMember("nonce") && json["nonce"].isUInt())
    setNonce(json["nonce"].asUInt());

  Log::get().debug("JSON decoded. Record has been initialized.");
}



Record::Record(const EdDSA_KEY& key,
               const EdDSA_SIG& sig,
               const std::shared_ptr<Botan::RSA_PublicKey>& hsKey,
               const RSA_SIGNATURE& hsSig,
               const std::string& type,
               const std::string& name,
               const std::string& pgp,
               const StringMap& subdomains,
               uint32_t rng,
               uint32_t nonce)
    : edKey_(key),
      edSig_(sig),
      serviceKey_(hsKey),
      serviceSig_(hsSig),
      type_(type),
      name_(name),
      contact_(pgp),
      subdomains_(subdomains),
      rng_(rng),
      nonce_(nonce)
{
}



Record::Record(const std::string& type,
               const std::string& name,
               const std::string& pgp,
               const StringMap& subdomains,
               uint32_t rng,
               uint32_t nonce)
    : type_(type),
      name_(name),
      contact_(pgp),
      subdomains_(subdomains),
      rng_(rng),
      nonce_(nonce)
{
  edKey_.fill(0);
  edSig_.fill(0);
  serviceSig_.fill(0);
  serviceKey_ = nullptr;
  Log::get().debug("Partial Record created.");
}



// ************************** ACTION METHODS ************************** //



std::string Record::resolve(const std::string& source) const
{
  // check TLD?
  Log::get().debug("Record resolving \"" + source + "\"...");

  if (source == name_)
    return computeOnion();

  // check subdomains
  for (auto sub : subdomains_)
    if (source == sub.first + "." + name_)
      return sub.second + "." + name_;

  // return empty string on failure
  return "";
}



// used to uniquely identify the record
Botan::SecureVector<uint8_t> Record::hash() const
{
  // Log::get().debug("Hashing record...");

  if (!serviceKey_)
  {
    // Log::get().debug("Record is not complete, returning blank hash.");
    Botan::SecureVector<uint8_t> empty(Const::SHA256_LEN);
    return empty;
  }

  Botan::SHA_256 sha;
  auto bytes = asBytes(true);
  return sha.process(Botan::MemoryVector<uint8_t>(bytes.data(), bytes.size()));
}



uint32_t Record::computePOW() const
{
  return computePOW(getProofOfWorkScope());
}



// returns first word, updates the second
uint32_t Record::computePOW(const PoW_SCOPE& scope)
{
  Botan::SHA_256 sha;

  uint32_t val;
  auto hashBytes = sha.process(scope.data(), scope.size());
  memcpy(&val, hashBytes, sizeof(uint32_t));
  return val;
}



double Record::computeWeight() const
{
  return computeWeight(getProofOfWorkScope());
}



double Record::computeWeight(const PoW_SCOPE& scope)
{
  static Botan::SHA_256 sha;
  auto hashBytes = sha.process(scope.data(), scope.size());

  uint32_t x, y;
  memcpy(&x, hashBytes + 1 * sizeof(uint32_t), sizeof(uint32_t));
  memcpy(&y, hashBytes + 2 * sizeof(uint32_t), sizeof(uint32_t));

  if (x == 0 && y == 0)  // prevents returning of NaN
    return std::pow(2, 64);
  else  // average the log of two words, then compute -log2(avg / 32)
    return -log2((log2(x) + log2(y)) / 64);
}



bool Record::computeValidity() const
{
  if (!serviceKey_)  // test if the Record is incompletely created
    return false;

  Log::get().debug("Checking the validity of the complete record...");

  // thanks to the PoPETS reviewer who suggested checking PoW first to avoid DoS
  return verifyPOW() && verifyEdDSA() && verifyServiceKey() &&
         verifyServiceSig() && verifyRNG() && verifySubdomains() &&
         verifyStrings();
}



std::string Record::computeOnion() const
{
  // https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt :
  // When we refer to "the hash of a public key", we mean the SHA-1 hash of the
  // DER encoding of an ASN.1 RSA public key (as specified in PKCS.1).

  if (!serviceKey_)
    return "";

  // perform SHA-1 of DER encoding of RSA key
  Botan::SHA_160 sha1;
  auto hash = sha1.process(serviceKey_->x509_subject_public_key());
  // "hash" is a technical term: https://sphincs.cr.yp.to/

  // encode, make lowercase, truncate, and return
  std::string hashStr(hash.size(), 0);
  std::copy(hash.begin(), hash.end(), hashStr.begin());
  std::string addr = base32::encode(hashStr);
  std::transform(addr.begin(), addr.end(), addr.begin(), ::tolower);
  // Log::get().debug("Complete onion hash is " + addr);
  return addr.substr(0, 16) + ".onion";
}



// RSA onion service sig is first, nonce is last
std::vector<uint8_t> Record::asBytes(bool includeMasterSig) const
{
  std::vector<uint8_t> bytes;  //(1024);

  if (!serviceKey_)  // test if Record is incompletely created
    return bytes;

  bytes.insert(bytes.end(), serviceSig_.begin(), serviceSig_.end());
  if (includeMasterSig)
    bytes.insert(bytes.end(), edSig_.begin(), edSig_.end());

  auto ber = getServicePublicKeyBER();
  bytes.insert(bytes.end(), ber.begin(), ber.end());
  bytes.insert(bytes.end(), edKey_.begin(), edKey_.end());

  for (auto sub : subdomains_)
  {
    bytes.insert(bytes.end(), sub.first.begin(), sub.first.end());
    bytes.insert(bytes.end(), sub.second.begin(), sub.second.end());
  }

  bytes.insert(bytes.end(), type_.begin(), type_.end());
  bytes.insert(bytes.end(), name_.begin(), name_.end());
  bytes.insert(bytes.end(), contact_.begin(), contact_.end());

  // add numbers
  std::array<uint8_t, sizeof(uint32_t) * 2> numbers;
  memcpy(numbers.data(), &rng_, sizeof(uint32_t));
  memcpy(numbers.data() + sizeof(uint32_t), &nonce_, sizeof(uint32_t));
  bytes.insert(bytes.end(), numbers.begin(), numbers.end());

  // Log::get().debug("asBytes, size " + std::to_string(bytes.size()));
  // Log::get().debug(Botan::base64_encode(numbers.data(), numbers.size()));
  return bytes;
}



Json::Value Record::asJSON() const
{
  Json::Value obj;

  // add keys
  obj["edKey"] = Botan::base64_encode(edKey_.data(), Const::EdDSA_KEY_LEN);
  obj["edSig"] = Botan::base64_encode(edSig_.data(), Const::EdDSA_SIG_LEN);
  obj["rsaSig"] = Botan::base64_encode(serviceSig_.data(), Const::RSA_SIG_LEN);
  if (serviceKey_)
    obj["rsaKey"] = Botan::base64_encode(getServicePublicKeyBER());

  // add various
  obj["type"] = type_;
  obj["name"] = name_;
  obj["rng"] = rng_;
  obj["nonce"] = nonce_;

  if (!contact_.empty())
    obj["pgp"] = contact_;

  for (auto sub : subdomains_)
    obj["subd"][sub.first] = sub.second;

  Log::get().debug("Record converted to JSON object.");

  return obj;
}



std::ostream& operator<<(std::ostream& os, const Record& r)
{
  Log::get().debug("Writing record to output stream...");

  bool valid = r.computeValidity();
  std::string onion = r.computeOnion();
  if (onion.empty())
    onion = "<unknown>";

  os << r.type_ << " record: (currently " << (valid ? "VALID)" : "INVALID)");

  os << "\n  Domain Information: ";
  os << "\n    " << r.name_ << " -> " << onion;

  if (r.subdomains_.empty())
    os << "\n    No subdomains";
  else
    for (auto subd : r.subdomains_)
      os << "\n    " << subd.first << "." << r.name_ << " -> " << subd.second;

  os << "\n    Onion key: ";
  if (r.serviceKey_)
  {
    auto pem = Botan::X509::PEM_encode(*r.serviceKey_);
    pem.pop_back();
    Utils::stringReplace(pem, "\n", "\n      ");
    os << "      \n\t" << pem << '\n';
  }
  else
    os << "      Missing!\n";

  os << "    Onion signature: ";
  os << Botan::base64_encode(r.serviceSig_.data(), r.serviceSig_.size() / 3)
     << " ...";

  os << "\n  Owner: ";
  os << "\n    Key: "
     << Botan::base64_encode(r.edKey_.data(), Const::EdDSA_KEY_LEN);
  os << "\n    Signature: "
     << Botan::base64_encode(r.edSig_.data(), Const::EdDSA_SIG_LEN / 2)
     << " ...";

  if (!r.contact_.empty())
    os << "\n    Contact: PGP 0x" << r.contact_;
  else
    os << "\n    Contact: <not present>";

  os << "\n  Validation:";
  os << "\n    Proof of Work: " << r.computePOW();
  os << (r.verifyPOW() ? " (valid)" : " (invalid)");
  os << "\n    Weight: " << r.computeWeight();
  os << "\n    Nonce: " << r.nonce_;
  os << "\n    Quorum tag: " << r.rng_;
  os << "\n  ID: " << Botan::base64_encode(r.hash());

  return os;
}



// ************************** VERIFICATION ************************** //



bool Record::verifyEdDSA() const
{  // edDSA signature - signs everything except itself

  auto bin = asBytes(false);
  switch (
      ed25519_sign_open(bin.data(), bin.size(), edKey_.data(), edSig_.data()))
  {
    case 0:
      Log::get().debug("Record has good EdDSA signature");
      return true;

    case 1:
      Log::get().warn("Record has bad EdDSA signature");
      return false;

    case -1:
      Log::get().warn("EdDSA cryptographic error while checking signature!");
      return false;
  }

  Log::get().error("Impossible return value from ed25519-donna!");
}



bool Record::verifyServiceKey() const
{
  if (!serviceKey_)  // need at least one key
    return false;

  // check public key
  auto size = serviceKey_->get_n().bits();
  if (serviceKey_ && size != Const::RSA_KEY_LEN)
  {
    Log::get().warn("Record has " + std::to_string(size) +
                    "-bit public key. Expected 1024-bit RSA.");
    return false;
  }

  Log::get().debug("Record RSA onion service key is good.");
  return true;
}



bool Record::verifyServiceSig() const
{
  // check signature
  auto bytes = getServiceSigningScope();
  Botan::PK_Verifier verifier(*serviceKey_, "EMSA-PSS(SHA-384)");
  if (!verifier.verify_message(bytes, bytes.size(), serviceSig_.data(),
                               Const::RSA_SIG_LEN))
  {
    Log::get().warn("Record's signature is not valid.");
    return false;
  }

  Log::get().debug("Record RSA onion service signature is good.");
  return true;
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

  if (!Utils::strEndsWith(name_, ".tor"))
  {
    Log::get().warn("Record name, \"" + name_ + "\", does not end in \".tor\"");
    return false;
  }

  if (contact_.size() > 40)
  {
    Log::get().warn("Record PGP fingerprint cannot exceed 40 bytes.");
    return false;
  }

  Log::get().debug("Record string values are good.");
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

  Log::get().debug("Record subdomains are good.");
  return true;
}



bool Record::verifyRNG() const
{
  Log::get().debug("Record CSPRNG value is good.");
  return true;  // todo
}



bool Record::verifyPOW() const
{
  if (!serviceKey_)
    return false;

  if (computePOW() > Const::PoW_THRESHOLD)
    return false;
  else
  {
    Log::get().debug("Record PoW value is below threshold.");
    return true;
  }
}



// ************************** GET METHODS ************************** //



Botan::MemoryVector<uint8_t> Record::getServicePublicKeyBER() const
{
  // https://en.wikipedia.org/wiki/X.690#BER_encoding
  auto ber = Botan::X509::BER_encode(*getServicePublicKey());
  Log::get().debug("BER key size: " + std::to_string(ber.size()));
  return ber;
}



Botan::MemoryVector<uint8_t> Record::getServiceSigningScope() const
{  // service sig - edDSA key, name, service key

  auto ber = getServicePublicKeyBER();
  Botan::MemoryVector<uint8_t> bytes(Const::EdDSA_KEY_LEN + name_.size() +
                                     ber.size());

  bytes.copy(bytes.size(), edKey_.data(), Const::EdDSA_KEY_LEN);
  bytes.copy(bytes.size(), reinterpret_cast<const uint8_t*>(name_.data()),
             name_.size());
  bytes.copy(bytes.size(), ber, ber.size());

  return bytes;
}



// returns edDSA key, edDSA sig, nonce
PoW_SCOPE Record::getProofOfWorkScope() const
{
  PoW_SCOPE scope;

  std::copy(edKey_.begin(), edKey_.end(), scope.begin());
  std::copy(edSig_.begin(), edSig_.end(), scope.begin() + Const::EdDSA_KEY_LEN);
  memcpy(scope.data() + Const::EdDSA_KEY_LEN + Const::EdDSA_SIG_LEN, &nonce_,
         sizeof(uint32_t));

  return scope;
}



std::shared_ptr<Botan::RSA_PublicKey> Record::getServicePublicKey() const
{
  return serviceKey_;
}



RSA_SIGNATURE Record::getServiceSignature() const
{
  return serviceSig_;
}



EdDSA_KEY Record::getMasterPublicKey() const
{
  return edKey_;
}



EdDSA_SIG Record::getMasterSignature() const
{
  return edSig_;
}



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



uint32_t Record::getRNG() const
{
  return rng_;
}



uint32_t Record::getNonce() const
{
  return nonce_;
}



// ************************** SET METHODS ************************** //



void Record::setMasterPublicKey(const EdDSA_KEY& key)
{
  edKey_ = key;
}



void Record::setMasterSignature(const EdDSA_SIG& sig)
{
  edSig_ = sig;
}



void Record::setServicePublicKey(
    const std::shared_ptr<Botan::RSA_PublicKey>& key)
{
  serviceKey_ = key;
}



void Record::setServiceSignature(const RSA_SIGNATURE& sig)
{
  serviceSig_ = sig;
}



void Record::setName(const std::string& name)
{
  name_ = name;
}


void Record::setType(const std::string& type)
{
  type_ = type;
}



void Record::setContact(const std::string& contact)
{
  contact_ = contact;
}


void Record::setSubdomains(const StringMap& subdomains)
{
  subdomains_ = subdomains;
}



void Record::setRNG(uint32_t rng)
{
  rng_ = rng;
}



void Record::setNonce(uint32_t nonce)
{
  nonce_ = nonce;
}
