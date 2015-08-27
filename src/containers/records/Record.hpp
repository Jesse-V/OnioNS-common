
#ifndef RECORD_HPP
#define RECORD_HPP

#include "../../Constants.hpp"
#include <botan/botan.h>
#include <botan/rsa.h>
#include <json/json.h>
#include <memory>
#include <cstdint>
#include <string>

typedef std::pair<uint8_t*, size_t> UInt8Array;
typedef std::vector<std::pair<std::string, std::string>> NameList;

class Record
{
 public:
  enum WorkStatus
  {
    Success,
    NotFound,
    Aborted
  };

  Record(Botan::RSA_PublicKey*);
  Record(Botan::RSA_PrivateKey*);
  Record(const Record&);
  virtual ~Record();

  void setName(const std::string&);
  std::string getName() const;

  void setSubdomains(const NameList&);
  NameList getSubdomains() const;

  void setContact(const std::string&);
  std::string getContact() const;

  bool setKey(Botan::RSA_PrivateKey*);
  UInt8Array getPublicKey() const;
  std::string getOnion() const;
  SHA384_HASH getHash() const;

  void makeValid(uint8_t);
  void computeValidity(bool*);  // updates valid_, with flag to abort work
  bool isValid() const;
  bool hasValidSignature() const;

  std::string getType() const;
  virtual uint32_t getDifficulty() const;
  virtual Json::Value asJSONObj() const;
  std::string asJSON() const;
  friend std::ostream& operator<<(std::ostream&, const Record&);

 protected:
  WorkStatus makeValid(uint8_t, uint8_t, bool*);
  virtual UInt8Array computeCentral();
  void updateAppendSignature(UInt8Array& buffer);
  int updateAppendScrypt(UInt8Array& buffer);
  void updateValidity(const UInt8Array& buffer);

  std::string type_, name_, contact_;
  NameList subdomains_;

  Botan::RSA_PrivateKey* privateKey_;
  Botan::RSA_PublicKey* publicKey_;

  std::array<uint8_t, Const::NONCE_LEN> nonce_;
  std::array<uint8_t, Const::SCRYPTED_LEN> scrypted_;
  std::array<uint8_t, Const::SIGNATURE_LEN> signature_;
  bool valid_, validSig_;
};

typedef std::shared_ptr<Record> RecordPtr;

#endif
