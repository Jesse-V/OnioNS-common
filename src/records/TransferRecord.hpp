
#ifndef TRANSFER_RECORD_HPP
#define TRANSFER_RECORD_HPP

#include "Record.hpp"

class TransferRecord : public Record
{
 public:
  TransferRecord(const std::shared_ptr<Botan::RSA_PublicKey>&);

 private:
  std::shared_ptr<Botan::RSA_PublicKey> recipientKey_;
};

#endif
