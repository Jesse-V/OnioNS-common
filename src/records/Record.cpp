
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
  memset(edKey_->data(), 0, Const::EdDSA_KEY_LEN);
  memset(edSig_->data(), 0, Const::EdDSA_SIG_LEN);
  memset(serviceSig_.data(), 0, Const::RSA_SIG_LEN);
  serviceKey_ = nullptr;
  nonce_ = rng_ = 0;

  if (json.isMember("edKey"))
  {
    std::string bytes =
        Utils::decodeBase64(json["edKey"].asString(), Const::EdDSA_KEY_LEN);
    std::copy(bytes.begin(), bytes.end(), edKey_->begin());
  }

  if (json.isMember("edSig"))
  {
    std::string bytes =
        Utils::decodeBase64(json["edSig"].asString(), Const::EdDSA_SIG_LEN);
    std::copy(bytes.begin(), bytes.end(), edSig_->begin());
  }

  if (json.isMember("rsaKey"))
  {
    std::string bytes =
        Utils::decodeBase64(json["rsaKey"].asString(), Const::RSA_KEY_LEN);
    if (!bytes.empty())
    {
      // interpret and parse into public RSA key
      std::istringstream iss(bytes);
      Botan::DataSource_Stream keyStream(iss);
      setServicePublicKey(std::make_shared<Botan::RSA_PublicKey>(
          *dynamic_cast<Botan::RSA_PublicKey*>(
              Botan::X509::load_key(keyStream))));
    }
  }

  if (json.isMember("rsaSig"))
  {
    std::string bytes =
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
SHA256_HASH Record::hash() const
{
  Json::FastWriter writer;
  std::string str = writer.write(asBytes());

  Botan::SHA_256 sha;
  SHA256_HASH hashBytes;
  auto shaHash = sha.process(str);
  std::copy(shaHash.begin(), shaHash.end(), hashBytes.begin());
  return hashBytes;
}



uint32_t Record::computePOW(const std::string& bytes) const
{
  Botan::SHA_256 sha;
  auto hashBytes = sha.process(
      reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size());

  SHA256_HASH hashArray;
  std::copy(hashBytes.begin(), hashBytes.begin() + 4, hashArray.begin());
  return *reinterpret_cast<uint16_t*>(hashArray.data());
}



bool Record::computeValidity() const
{
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

  // get DER encoding of RSA key
  std::string keyBinStr;
  auto x509Key = serviceKey_->x509_subject_public_key();
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



// last four bytes is the nonce
std::string Record::asBytes(bool forSigning) const
{
  std::string bytes;
  bytes.reserve(1024);

  bytes += type_ + name_ + contact_;
  for (auto sub : subdomains_)
    bytes += sub.first + sub.second;

  bytes += getServicePublicKeyBER();
  bytes.insert(bytes.size(), reinterpret_cast<const char*>(edKey_->data()),
               Const::EdDSA_KEY_LEN);

  if (!forSigning)
  {  // include EdDSA and RSA signatures
    bytes.insert(bytes.size(), reinterpret_cast<const char*>(edSig_->data()),
                 Const::EdDSA_SIG_LEN);
    bytes.insert(bytes.size(),
                 reinterpret_cast<const char*>(serviceSig_.data()),
                 Const::RSA_SIG_LEN);
  }

  // add numbers
  bytes.insert(bytes.size(), reinterpret_cast<const char*>(&rng_), 4);
  bytes.insert(bytes.size(), reinterpret_cast<const char*>(&nonce_), 4);
  Log::get().debug("Byte size: " + std::to_string(bytes.size()));
  return bytes;
}



Json::Value Record::asJSON() const
{
  Json::Value obj;

  // add keys
  auto rsa_ber = getServicePublicKeyBER();
  obj["edKey"] = Botan::base64_encode(edKey_->data(), Const::EdDSA_KEY_LEN);
  obj["edSig"] = Botan::base64_encode(edSig_->data(), Const::EdDSA_SIG_LEN);
  obj["rsaKey"] = Botan::base64_encode(
      reinterpret_cast<const unsigned char*>(rsa_ber.data()), rsa_ber.size());
  obj["rsaSig"] = Botan::base64_encode(serviceSig_.data(), Const::RSA_SIG_LEN);

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

  os << r.type_ << " record: (currently " << (valid ? "VALID)" : "INVALID)")
     << std::endl
     << std::endl;

  os << "  Domain Information: " << std::endl;
  os << "    " << r.name_ << " -> " << onion << std::endl;
  for (auto subd : r.subdomains_)
    os << "      " << subd.first << "." << r.name_ << " -> " << subd.second
       << std::endl
       << std::endl;

  os << "  Owner: " << std::endl;
  os << "    Key: "
     << Botan::base64_encode(r.edKey_->data(), Const::EdDSA_KEY_LEN)
     << std::endl;
  os << "    Signature: "
     << Botan::base64_encode(r.edSig_->data(), Const::EdDSA_SIG_LEN)
     << std::endl;
  if (r.contact_.empty())
    os << "    Contact: PGP 0x" << r.contact_ << std::endl << std::endl;


  os << "  Validation:" << std::endl;
  os << "    Proof of Work: " << r.computePOW(r.asBytes())
     << (r.verifyPOW() ? " (valid)" : " (invalid)") << std::endl;
  os << "    Nonce: " << r.nonce_ << std::endl;
  os << "    Quorum tag: " << r.rng_;
  /*
     os << "   Signature: ";
     if (valid)
       os << Botan::base64_encode(r.serviceSig_.data(), r.serviceSig_.size() /
     4)
          << " ..." << std::endl;
     else
       os << "<regeneration required>" << std::endl;

     auto pem = Botan::X509::PEM_encode(*r.publicKey_);
     pem.pop_back();  // delete trailing /n
     Utils::stringReplace(pem, "\n", "\n\t");
     os << "      RSA Public Key: \n\t" << pem;
  */
  return os;
}



// ************************** VERIFICATION ************************** //



bool Record::verifyEdDSA() const
{  // edDSA signature - edDSA key, name, destinations, data, nonce
  std::string bStr = asBytes(true);
  const uint8_t* bytes = reinterpret_cast<const uint8_t*>(bStr.data());

  switch (ed25519_sign_open(bytes, bStr.size(), edKey_->data(), edSig_->data()))
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
  std::string edKeyStr(reinterpret_cast<const char*>(edKey_->data()),
                       Const::EdDSA_KEY_LEN);
  std::string bytesStr = edKeyStr + name_ + getServicePublicKeyBER();

  // check signature
  auto bytes = reinterpret_cast<const unsigned char*>(bytesStr.data());
  Botan::PK_Verifier verifier(*serviceKey_, "EMSA-PSS(SHA-512)");
  if (!verifier.verify_message(bytes, bytesStr.size(), serviceSig_.data(),
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
  return computePOW(asBytes(true)) > Const::POW_WORD_0;
}



// ************************** GET METHODS ************************** //



std::string Record::getServicePublicKeyBER() const
{
  // https://en.wikipedia.org/wiki/X.690#BER_encoding
  std::string berBin;
  auto ber = Botan::X509::BER_encode(*getServicePublicKey());
  std::copy(ber.begin(), ber.end(), berBin.begin());
  Log::get().notice("BER size: " + std::to_string(ber.size()));
  return berBin;
}



EdDSA_KEY Record::getMasterPublicKey() const
{
  return edKey_;
}



EdDSA_SIG Record::getMasterSignature() const
{
  return edSig_;
}



std::shared_ptr<Botan::RSA_PublicKey> Record::getServicePublicKey() const
{
  return serviceKey_;
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
