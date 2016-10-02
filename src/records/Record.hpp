
#ifndef RECORD_HPP
#define RECORD_HPP

#include "../Constants.hpp"
#include <botan/botan.h>
#include <botan/rsa.h>
#include <jsoncpp/json/json.h>
#include <string>
#include <vector>
#include <memory>

#include "ed25519-donna/ed25519.h"

typedef std::vector<std::pair<std::string, std::string>> StringMap;

class Record
{
 public:
  Record(const Json::Value&);
  Record(const std::string&,
         const std::string&,
         const std::string&,
         const StringMap&,
         uint32_t,
         uint32_t);
  Record(const EdDSA_KEY&,
         const EdDSA_SIG&,
         const std::shared_ptr<Botan::RSA_PublicKey>&,
         const RSA_SIGNATURE&,
         const std::string&,
         const std::string&,
         const std::string&,
         const StringMap&,
         uint32_t,
         uint32_t);

  // action methods
  std::string resolve(const std::string&) const;
  Botan::SecureVector<uint8_t> hash() const;
  uint32_t computePOW(const std::vector<uint8_t>&) const;
  bool computeValidity() const;
  std::string computeOnion() const;
  std::vector<uint8_t> asBytes(bool forSigning = false) const;
  Json::Value asJSON() const;
  friend std::ostream& operator<<(std::ostream&, const Record&);

  // set methods
  void setMasterPublicKey(const EdDSA_KEY&);
  void setMasterSignature(const EdDSA_SIG&);
  void setServicePublicKey(const std::shared_ptr<Botan::RSA_PublicKey>&);
  void setServiceSignature(const RSA_SIGNATURE&);
  void setType(const std::string&);
  void setName(const std::string&);
  void setContact(const std::string&);
  void setSubdomains(const StringMap&);
  void setRNG(uint32_t);
  void setNonce(uint32_t);

  // get methods
  EdDSA_KEY getMasterPublicKey() const;
  EdDSA_SIG getMasterSignature() const;
  std::shared_ptr<Botan::RSA_PublicKey> getServicePublicKey() const;
  Botan::MemoryVector<uint8_t> getServicePublicKeyBER() const;
  RSA_SIGNATURE getServiceSignature() const;
  Botan::MemoryVector<uint8_t> getServiceSigningScope() const;
  std::string getType() const;
  std::string getName() const;
  std::string getContact() const;
  StringMap getSubdomains() const;
  uint32_t getRNG() const;
  uint32_t getNonce() const;

 private:
  bool verifyEdDSA() const;
  bool verifyServiceKey() const;
  bool verifyServiceSig() const;
  bool verifyStrings() const;
  bool verifySubdomains() const;
  bool verifyRNG() const;
  bool verifyPOW() const;

  EdDSA_KEY edKey_;
  EdDSA_SIG edSig_;
  std::shared_ptr<Botan::RSA_PublicKey> serviceKey_;
  RSA_SIGNATURE serviceSig_;
  std::string type_, name_, contact_;
  StringMap subdomains_;
  uint32_t rng_, nonce_;
};

typedef std::shared_ptr<Record> RecordPtr;

#endif
