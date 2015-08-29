
#ifndef REPLY_HPP
#define REPLY_HPP

#include "Enums.hpp"
#include <cstdint>
#include <string>
#include <boost/asio.hpp>

namespace Socks5
{
class Reply
{
 public:
  Reply() {}
  Reply(const boost::asio::mutable_buffer&);

  uint8_t getVersion() const;
  ReplyCode getReply() const;
  AddressType getAddrType() const;
  std::string getAddress() const;
  uint16_t getPort() const;

 private:
  const uint8_t version_ = 0x05;
  ReplyCode reply_;
  AddressType addressType_;
  std::string address_;
  uint16_t port_;
};
}

#endif
