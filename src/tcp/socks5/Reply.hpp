
#ifndef REPLY_HPP
#define REPLY_HPP

#include "AddressType.hpp"
#include "ReplyCode.hpp"

#include <cstdint>
#include <string>
#include <boost/asio.hpp>

namespace Socks5
{
class Reply
{
 public:
  Reply() {}
  Reply(boost::asio::mutable_buffer);

  uint8_t version() const;
  ReplyCode reply() const;
  AddressType atype() const;
  std::string address() const;
  uint16_t port() const;

  void from_buffer(boost::asio::mutable_buffer);

 private:
  const uint8_t version_ = 0x05;
  ReplyCode reply_;
  // const uint8_t reserved = 0x00;
  AddressType address_type_;
  std::string address_;
  uint16_t port_;
};
}

#endif
