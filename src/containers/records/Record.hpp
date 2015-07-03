
#ifndef RECORD_HPP
#define RECORD_HPP

#include "../../Constants.hpp"
#include <botan-1.10/botan/botan.h>
#include <botan-1.10/botan/rsa.h>
#include <memory>
#include <cstdint>
#include <string>

typedef std::pair<uint8_t*, size_t> UInt8Array;
typedef std::vector<std::pair<std::string, std::string>> NameList;

class Record
{
 public:
  static const uint64_t SCR_N = 1 << 20;  // RAM load = O(SCR_N)
  static const uint32_t SCR_P = 1 << 0;   // CPU time = O(SCR_N * SCR_P)

  static const uint8_t NONCE_LEN = 4;
  static const uint8_t SCRYPTED_LEN = 16;

  enum WorkStatus
  {
    Success,
    NotFound,
    Aborted
  };

  Record(Botan::RSA_PublicKey*);
  Record(Botan::RSA_PrivateKey*, uint8_t*);
  Record(const Record&);

  void setName(const std::string&);
  std::string getName() const;

  void setSubdomains(const NameList&);
  NameList getSubdomains() const;

  void setContact(const std::string&);
  std::string getContact() const;

  bool setKey(Botan::RSA_PrivateKey*);
  UInt8Array getPublicKey() const;
  std::string getOnion() const;
  uint8_t* getHash() const;

  bool refresh();
  void makeValid(uint8_t);
  void computeValidity(bool*);  // updates valid_, with flag to abort work
  bool isValid() const;
  bool hasValidSignature() const;

  // virtual bool makeValid(uint8_t);
  std::string getType() const;
  virtual uint32_t getDifficulty() const;
  virtual std::string asJSON() const;
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

  uint8_t consensusHash_[Const::SHA384_LEN];
  uint8_t nonce_[NONCE_LEN];
  uint8_t scrypted_[SCRYPTED_LEN];
  uint8_t signature_[Const::SIGNATURE_LEN];
  long timestamp_;
  bool valid_, validSig_;
};

typedef std::shared_ptr<Record> RecordPtr;

#endif
