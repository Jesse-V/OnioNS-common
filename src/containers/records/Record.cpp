
#include "Record.hpp"
#include "../Utils.hpp"
#include "../../Log.hpp"

#include <libscrypt/libscrypt.h>
#include <botan/pubkey.h>
#include <botan/sha160.h>
#include <botan/sha2_64.h>
#include <botan/base64.h>
#include <CyoEncode/CyoEncode.hpp>
#include <json/json.h>

#include <thread>
#include <cassert>


Record::Record(Botan::RSA_PublicKey* pubKey)
    : privateKey_(nullptr), publicKey_(pubKey), valid_(false), validSig_(false)
{
  memset(nonce_, 0, NONCE_LEN);
  memset(scrypted_, 0, SCRYPTED_LEN);
  memset(signature_, 0, Const::SIGNATURE_LEN);
}



Record::Record(Botan::RSA_PrivateKey* key)
    : Record(static_cast<Botan::RSA_PublicKey*>(key))
{
  assert(key->get_n().bits() == Const::RSA_LEN);
  setKey(key);
}



Record::Record(const Record& other)
    : type_(other.type_),
      name_(other.name_),
      contact_(other.contact_),
      subdomains_(other.subdomains_),
      privateKey_(other.privateKey_),
      publicKey_(other.publicKey_),
      valid_(other.valid_),
      validSig_(other.validSig_)
{
  memcpy(nonce_, other.nonce_, NONCE_LEN);
  memcpy(scrypted_, other.scrypted_, SCRYPTED_LEN);
  memcpy(signature_, other.signature_, Const::SIGNATURE_LEN);
}



Record::~Record()
{
  delete privateKey_;
  delete publicKey_;
}



void Record::setName(const std::string& name)
{
  // todo: check for valid name characters

  if (name.length() < 5 || name.length() > 128)
    throw std::invalid_argument("Name \"" + name + "\" has invalid length!");

  if (!Utils::strEndsWith(name, ".tor"))
    throw std::invalid_argument("Name \"" + name + "\" must end with .tor!");

  name_ = name;
  valid_ = false;
}



std::string Record::getName() const
{
  return name_;
}



void Record::setSubdomains(const NameList& subdomains)
{
  // todo: count/check number and length of names

  if (subdomains.size() > 24)
    throw std::invalid_argument("Cannot have more than 24 subdomains!");

  for (auto pair : subdomains)
  {
    if (pair.first.length() == 0 || pair.first.length() > 128)
      throw std::invalid_argument("Invalid length of subdomain!");
    if (pair.second.length() == 0 || pair.second.length() > 128)
      throw std::invalid_argument("Invalid length of destination!");

    if (Utils::strEndsWith(pair.first, name_))
      throw std::invalid_argument("Subdomain should not contain name");
    if (!Utils::strEndsWith(pair.second, ".tor") &&
        !Utils::strEndsWith(pair.second, ".onion"))
      throw std::invalid_argument("Destination must go to .tor or .onion!");
  }

  subdomains_ = subdomains;
  valid_ = false;
}



NameList Record::getSubdomains() const
{
  return subdomains_;
}



void Record::setContact(const std::string& contactInfo)
{
  if (!Utils::isPowerOfTwo(contactInfo.length()))
    throw std::invalid_argument("Invalid length of PGP key");

  contact_ = contactInfo;
  valid_ = false;
}



std::string Record::getContact() const
{
  return contact_;
}



bool Record::setKey(Botan::RSA_PrivateKey* key)
{
  if (key == NULL)
    return false;

  privateKey_ = key;
  valid_ = false;  // need new nonce now
  return true;
}



UInt8Array Record::getPublicKey() const
{
  // https://en.wikipedia.org/wiki/X.690#BER_encoding
  auto bem = Botan::X509::BER_encode(*publicKey_);
  uint8_t* val = new uint8_t[bem.size()];
  memcpy(val, bem, bem.size());

  return std::make_pair(val, bem.size());
}



std::string Record::getOnion() const
{
  // https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt :
  // When we refer to "the hash of a public key", we mean the SHA-1 hash of the
  // DER encoding of an ASN.1 RSA public key (as specified in PKCS.1).

  // get DER encoding of RSA key
  auto x509Key = publicKey_->x509_subject_public_key();
  char* derEncoded = new char[x509Key.size()];
  memcpy(derEncoded, x509Key, x509Key.size());

  // perform SHA-1
  Botan::SHA_160 sha1;
  auto hash = sha1.process(std::string(derEncoded, x509Key.size()));
  delete[] derEncoded;

  // perform base32 encoding
  char onionB32[Const::SHA1_LEN * 4];
  CyoEncode::Base32::Encode(onionB32, hash, Const::SHA1_LEN);

  // truncate, make lowercase, and return result
  auto addr = std::string(onionB32, 16);
  std::transform(addr.begin(), addr.end(), addr.begin(), ::tolower);
  return addr + ".onion";
}



uint8_t* Record::getHash() const
{
  Botan::SHA_384 sha;
  uint8_t* hash = sha.process(asJSON());
  return hash;
}



void Record::makeValid(uint8_t nWorkers)
{
  if (nWorkers == 0)
    throw std::invalid_argument("Not enough workers");

  Log::get().notice("Making the Record valid... \n");

  bool found = false;
  bool* foundSig = &found;

  std::vector<std::thread> workers;
  for (uint8_t n = 0; n < nWorkers; n++)
  {
    workers.push_back(std::thread(
        [n, nWorkers, foundSig, this]()
        {
          std::string name("worker " + std::to_string(n + 1));

          Log::get().notice("Starting " + name);

          auto record = std::make_shared<Record>(*this);
          record->nonce_[NONCE_LEN - 1] = n;
          if (record->makeValid(0, nWorkers, foundSig) == WorkStatus::Success)
          {
            Log::get().notice("Success from " + name);

            // save successful answer
            memcpy(nonce_, record->nonce_, NONCE_LEN);
            memcpy(scrypted_, record->scrypted_, SCRYPTED_LEN);
            memcpy(signature_, record->signature_, Const::SIGNATURE_LEN);
            valid_ = true;
          }

          Log::get().notice("Shutting down " + name);
        }));
  }

  std::for_each(workers.begin(), workers.end(), [](std::thread& t)
                {
                  t.join();
                });

  bool tmp = false;
  computeValidity(&tmp);  // todo: faster way than this?
}



bool Record::isValid() const
{
  return valid_;
}



bool Record::hasValidSignature() const
{
  return validSig_;
}



std::string Record::getType() const
{
  return type_;
}



uint32_t Record::getDifficulty() const
{
  return 7;  // 1/2^x chance of success, so order of magnitude
}



std::string Record::asJSON() const
{
  Json::Value obj;

  obj["type"] = type_;
  obj["contact"] = contact_;
  obj["name"] = name_;

  // add subdomains
  for (auto sub : subdomains_)
    obj["subd"][sub.first] = sub.second;

  // extract and save public key
  auto key = getPublicKey();
  obj["pubHSKey"] = Botan::base64_encode(key.first, key.second);

  // if the domain is valid, add nonce_, scrypted_, and signature_
  if (isValid())
  {
    obj["nonce"] = Botan::base64_encode(nonce_, NONCE_LEN);
    obj["pow"] = Botan::base64_encode(scrypted_, SCRYPTED_LEN);
    obj["recordSig"] = Botan::base64_encode(signature_, Const::SIGNATURE_LEN);
  }

  // output in compressed (non-human-friendly) format
  Json::FastWriter writer;
  return writer.write(obj);
}



std::ostream& operator<<(std::ostream& os, const Record& dt)
{
  os << "Domain Registration: (currently "
     << (dt.valid_ ? "VALID)" : "INVALID)") << std::endl;

  os << "   Domain Information: " << std::endl;
  os << "      " << dt.name_ << " -> " << dt.getOnion() << std::endl;
  for (auto subd : dt.subdomains_)
    os << "      " << subd.first << "." << dt.name_ << " -> " << subd.second
       << std::endl;

  os << "   Contact: PGP 0x" << dt.contact_ << std::endl;
  os << "   Validation:" << std::endl;

  os << "   Nonce: ";
  if (dt.isValid())
    os << Botan::base64_encode(dt.nonce_, dt.NONCE_LEN) << std::endl;
  else
    os << "<regeneration required>" << std::endl;

  os << "      Proof of Work: ";
  if (dt.isValid())
    os << Botan::base64_encode(dt.scrypted_, dt.SCRYPTED_LEN) << std::endl;
  else
    os << "<regeneration required>" << std::endl;

  os << "      Signature: ";
  if (dt.isValid())
    os << Botan::base64_encode(dt.signature_, Const::SIGNATURE_LEN / 4)
       << " ..." << std::endl;
  else
    os << "<regeneration required>" << std::endl;

  auto pem = Botan::X509::PEM_encode(*dt.publicKey_);
  pem.pop_back();  // delete trailing /n
  Utils::stringReplace(pem, "\n", "\n\t");
  os << "      RSA Public Key: \n\t" << pem;

  return os;
}



// ***************************** PRIVATE METHODS *****************************



Record::WorkStatus Record::makeValid(uint8_t depth, uint8_t inc, bool* abortSig)
{
  if (isValid())
    return WorkStatus::Aborted;

  if (depth > NONCE_LEN)
    return WorkStatus::NotFound;

  // base case
  if (depth == NONCE_LEN)
  {
    computeValidity(abortSig);  // abortSig stops check

    if (isValid())
    {                    // stop processing if found valid
      *abortSig = true;  // alert other workers
      return WorkStatus::Success;
    }

    return *abortSig ? WorkStatus::Aborted : WorkStatus::NotFound;
  }

  WorkStatus ret = makeValid(depth + 1, inc, abortSig);
  if (ret == WorkStatus::Success || ret == WorkStatus::Aborted)
    return ret;

  while (nonce_[depth] < UINT8_MAX)
  {
    nonce_[depth] += inc;
    ret = makeValid(depth + 1, inc, abortSig);
    if (ret == WorkStatus::Success || ret == WorkStatus::Aborted)
      return ret;
  }

  nonce_[depth] = 0;
  return WorkStatus::NotFound;
}



void Record::computeValidity(bool* abortSig)
{
  UInt8Array buffer = computeCentral();

  if (*abortSig)
    return;

  // updated scrypted_, append scrypted_ to buffer, check for errors
  if (updateAppendScrypt(buffer) < 0)
  {
    Log::get().warn("Error with scrypt call!");
    return;
  }

  if (*abortSig)  // stop if another worker has won
    return;

  updateAppendSignature(buffer);  // update signature_, append to buffer
  updateValidity(buffer);         // update valid_ based on entire buffer
  delete buffer.first;            // cleanup
}



// allocates a buffer big enough to append
// scrypted_ and signature_ without buffer overflow
UInt8Array Record::computeCentral()
{
  std::string str(type_ + name_);
  for (auto pair : subdomains_)
    str += pair.first + pair.second;
  str += contact_;

  int index = 0;
  auto pubKey = getPublicKey();
  const size_t centralLen = str.length() + NONCE_LEN + pubKey.second;
  uint8_t* central =
      new uint8_t[centralLen + SCRYPTED_LEN + Const::SIGNATURE_LEN];

  memcpy(central + index, str.c_str(), str.size());  // copy string into array
  index += str.size();

  memcpy(central + index, nonce_, NONCE_LEN);
  index += NONCE_LEN;

  memcpy(central + index, pubKey.first, pubKey.second);

  // std::cout << Botan::base64_encode(central, centralLen) << std::endl;
  return std::make_pair(central, centralLen);
}



// signs buffer, saving to signature_, appends signature to buffer
void Record::updateAppendSignature(UInt8Array& buffer)
{
  static Botan::AutoSeeded_RNG rng;

  if (privateKey_)
  {  // if we have a key, sign it
    // https://stackoverflow.com/questions/14263346/how-to-perform-asymmetric-encryption-with-botan
    // http://botan.randombit.net/manual/pubkey.html#signatures
    Botan::PK_Signer signer(*privateKey_, "EMSA-PKCS1-v1_5(SHA-384)");
    auto sig = signer.sign_message(buffer.first, buffer.second, rng);
    validSig_ = true;

    assert(sig.size() == Const::SIGNATURE_LEN);
    memcpy(signature_, sig, sig.size());
  }
  else
  {  // we are validating a public Record, so confirm the signature
    Botan::PK_Verifier verifier(*publicKey_, "EMSA-PKCS1-v1_5(SHA-384)");
    validSig_ = verifier.verify_message(buffer.first, buffer.second, signature_,
                                        Const::SIGNATURE_LEN);
  }

  // append into buffer
  memcpy(buffer.first + buffer.second, signature_, Const::SIGNATURE_LEN);
  buffer.second += Const::SIGNATURE_LEN;
}



// performs scrypt on buffer, appends result to buffer, returns scrypt status
int Record::updateAppendScrypt(UInt8Array& buffer)
{
  // allocate and prepare static salt
  static uint8_t* const SALT = new uint8_t[SCRYPT_SALT_LEN];
  static bool saltReady = false;
  if (!saltReady)
  {
    assert(SCRYPT_SALT_LEN == 16);
    std::string piHex("243F6A8885A308D313198A2E03707344");  // pi in hex
    Utils::hex2bin(reinterpret_cast<const uint8_t*>(piHex.c_str()), SALT);
    saltReady = true;
  }

  // compute scrypt
  auto r = libscrypt_scrypt(buffer.first, buffer.second, SALT, SCRYPT_SALT_LEN,
                            SCR_N, 1, SCR_P, scrypted_, SCRYPTED_LEN);

  // append scrypt output to buffer
  memcpy(buffer.first + buffer.second, scrypted_, SCRYPTED_LEN);
  buffer.second += SCRYPTED_LEN;

  return r;
}



// checks whether the Record is valid based on the hash of the buffer
void Record::updateValidity(const UInt8Array& buffer)
{
  // hash entire buffer and convert hash to number
  Botan::SHA_384 sha384;
  auto hash = sha384.process(buffer.first, buffer.second);
  auto num = Utils::arrayToUInt32(hash, 0);

  // compare number against threshold

  if (num < UINT32_MAX / (1 << getDifficulty()))
    valid_ = true;
  else
  {
    Log::get().notice(Botan::base64_encode(nonce_, NONCE_LEN) +
                      " -> not valid");
  }
}
