
#ifndef RECORD_HPP
#define RECORD_HPP

#include "../Constants.hpp"
#include <botan/botan.h>
#include <botan/rsa.h>
#include <jsoncpp/json/json.h>
#include <string>
#include <vector>
#include <memory>

typedef std::vector<std::pair<std::string, std::string>> StringMap;

class Record
{
 public:
  Record(const std::shared_ptr<Botan::RSA_PrivateKey>&);
  Record(const Json::Value&);

  // action methods
  std::string resolve(const std::string&) const;
  SHA256_HASH computeValue() const;
  bool computeValidity() const;
  SHA256_HASH hash() const;
  void sign();
  std::string computeOnion() const;
  Json::Value asJSON() const;
  friend std::ostream& operator<<(std::ostream&, const Record&);

  // set methods
  void setType(const std::string&);
  void setName(const std::string&);
  void setContact(const std::string&);
  void setSubdomains(const StringMap&);
  void setSecondaryAddresses(const std::vector<std::string>&);
  void setPrivateKey(const std::shared_ptr<Botan::RSA_PrivateKey>&);

  // get methods
  std::string getType() const;
  std::string getName() const;
  std::string getContact() const;
  StringMap getSubdomains() const;
  std::vector<std::string> getSecondaryAddresses() const;
  std::shared_ptr<Botan::RSA_PublicKey> getPublicKey() const;
  UInt8Array getPublicKeyBER() const;
  RSA_SIGNATURE getSignature() const;

 private:
  bool verifyStrings() const;
  bool verifySubdomains() const;
  bool verifySecondaryAddrs() const;
  bool verifyKeys() const;
  bool verifySignature() const;

  std::string type_, name_, contact_;
  StringMap subdomains_;
  std::vector<std::string> secondaryAddrs_;
  std::shared_ptr<Botan::RSA_PrivateKey> privateKey_;
  std::shared_ptr<Botan::RSA_PublicKey> publicKey_;
  RSA_SIGNATURE signature_;
  // missing beacon, missing a validity/proper flag?
};


typedef std::shared_ptr<Record> RecordPtr;

#endif
