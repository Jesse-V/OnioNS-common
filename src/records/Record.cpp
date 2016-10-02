
#include "Record.hpp"
#include "../Log.hpp"
#include "../Utils.hpp"
#include "cppcodec/cppcodec/base32_default_rfc4648.hpp"
#include <botan/pubkey.h>
#include <botan/sha2_32.h>
#include <botan/sha160.h>
#include <botan/base64.h>
#include <sstream>


Record::Record(const Json::Value& json)  // reciprocal of asJSON
{
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
}



// ************************** ACTION METHODS ************************** //



std::string Record::resolve(const std::string& source) const
{
  // check TLD?

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
  if (!serviceKey_)
  {
    Botan::SecureVector<uint8_t> empty(Const::SHA256_LEN);
    return empty;
  }

  Botan::SHA_256 sha;
  auto bytes = asBytes();
  return sha.process(Botan::MemoryVector<uint8_t>(bytes.data(), bytes.size()));
}



uint32_t Record::computePOW(const std::vector<uint8_t>& bytes) const
{
  Botan::SHA_256 sha;
  auto hashBytes = sha.process(bytes.data(), bytes.size());

  std::array<uint8_t, 4> value;
  std::copy(hashBytes.begin(), hashBytes.end(), value.begin());
  return *reinterpret_cast<uint16_t*>(value.data());
}



bool Record::computeValidity() const
{
  if (!serviceKey_)  // test if the Record is incompletely created
    return false;

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
  std::string hashStr;
  std::copy(hash.begin(), hash.end(), hashStr.begin());
  std::string addr = base32::encode(hashStr);
  std::transform(addr.begin(), addr.end(), addr.begin(), ::tolower);
  return std::string(addr, 16) + ".onion";
}



// last four bytes is the nonce
std::vector<uint8_t> Record::asBytes(bool forSigning) const
{
  std::vector<uint8_t> bytes(1024);

  if (!serviceKey_)  // test if Record is incompletely created
    return bytes;

  bytes.insert(bytes.end(), type_.begin(), type_.end());
  bytes.insert(bytes.end(), name_.begin(), name_.end());
  bytes.insert(bytes.end(), contact_.begin(), contact_.end());

  for (auto sub : subdomains_)
  {
    bytes.insert(bytes.end(), sub.first.begin(), sub.first.end());
    bytes.insert(bytes.end(), sub.second.begin(), sub.second.end());
  }

  auto ber = getServicePublicKeyBER();
  bytes.insert(bytes.end(), ber.begin(), ber.end());
  bytes.insert(bytes.end(), edKey_.begin(), edKey_.end());

  if (!forSigning)
  {  // include EdDSA and RSA signatures
    bytes.insert(bytes.end(), edSig_.begin(), edSig_.end());
    bytes.insert(bytes.end(), serviceSig_.begin(), serviceSig_.end());
  }

  // add numbers
  std::array<uint8_t, 8> numbers;
  memcpy(numbers.data(), &rng_, 4);
  memcpy(numbers.data(), &nonce_, 4);
  bytes.insert(bytes.end(), numbers.begin(), numbers.end());

  Log::get().debug("Byte size: " + std::to_string(bytes.size()));
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

  return obj;
}



std::ostream& operator<<(std::ostream& os, const Record& r)
{
  bool valid = r.computeValidity();
  std::string onion = r.computeOnion();
  if (onion.empty())
    onion = "<unknown>";

  os << r.type_ << " record: (currently " << (valid ? "VALID)" : "INVALID)")
     << std::endl;

  os << "  Domain Information: " << std::endl;
  os << "    " << r.name_ << " -> " << onion << std::endl;

  if (r.subdomains_.empty())
    os << "    No subdomains" << std::endl;
  else
    for (auto subd : r.subdomains_)
      os << "    " << subd.first << "." << r.name_ << " -> " << subd.second
         << std::endl;

  os << "    Onion key: ";
  if (r.serviceKey_)
  {
    auto pem = Botan::X509::PEM_encode(*r.serviceKey_);
    pem.pop_back();
    Utils::stringReplace(pem, "\n", "\n\t");
    os << "      \n\t" << pem;
  }
  else
    os << "      Missing!" << std::endl;

  os << "    Onion signature: ";
  os << Botan::base64_encode(r.serviceSig_.data(), r.serviceSig_.size() / 4)
     << " ..." << std::endl;

  os << "  Owner: " << std::endl;
  os << "    Key: "
     << Botan::base64_encode(r.edKey_.data(), Const::EdDSA_KEY_LEN)
     << std::endl;
  os << "    Signature: "
     << Botan::base64_encode(r.edSig_.data(), Const::EdDSA_SIG_LEN)
     << std::endl;

  if (!r.contact_.empty())
    os << "    Contact: PGP 0x" << r.contact_ << std::endl;
  else
    os << "    Contact: <not present>" << std::endl;

  os << "  Validation:" << std::endl;

  os << "    Proof of Work:";
  if (r.serviceKey_)
    os << " " << r.computePOW(r.asBytes());
  os << (r.verifyPOW() ? " (valid)" : " (invalid)") << std::endl;

  os << "    Nonce: " << r.nonce_ << std::endl;
  os << "    Quorum tag: " << r.rng_ << std::endl;

  os << "  ID: " << Botan::base64_encode(r.hash()) << std::endl;

  return os;
}



// ************************** VERIFICATION ************************** //



bool Record::verifyEdDSA() const
{  // edDSA signature - edDSA key, name, destinations, data, nonce
  auto bin = asBytes(true);
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
      Log::get().error("EdDSA cryptographic error while checking signature!");
      return false;
  }

  Log::get().error("Impossible return value from ed25519-donna!");
  return false;
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

  return true;
}



bool Record::verifyServiceSig() const
{
  // check signature
  auto bytes = getServiceSigningScope();
  Botan::PK_Verifier verifier(*serviceKey_, "EMSA-PSS(SHA-512)");
  if (!verifier.verify_message(bytes, bytes.size(), serviceSig_.data(),
                               Const::RSA_SIG_LEN))
  {
    Log::get().warn("Record's signature is not valid.");
    return false;
  }

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



bool Record::verifyRNG() const
{
  return true;  // todo
}



bool Record::verifyPOW() const
{
  if (!serviceKey_)
    return false;

  return true;  // todo
  // return computePOW(asBytes(true)) <= Const::POW_WORD_0;
}



// ************************** GET METHODS ************************** //



Botan::MemoryVector<uint8_t> Record::getServicePublicKeyBER() const
{
  // https://en.wikipedia.org/wiki/X.690#BER_encoding
  auto ber = Botan::X509::BER_encode(*getServicePublicKey());
  Log::get().notice("BER size: " + std::to_string(ber.size()));
  return ber;
}



Botan::MemoryVector<uint8_t> Record::getServiceSigningScope() const
{
  Botan::MemoryVector<uint8_t> bytes(1024);
  bytes.copy(bytes.size(), edKey_.data(), Const::EdDSA_KEY_LEN);
  bytes.copy(bytes.size(), reinterpret_cast<const uint8_t*>(name_.data()),
             name_.size());

  auto ber = getServicePublicKeyBER();
  bytes.copy(bytes.size(), ber, ber.size());
  return bytes;
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
