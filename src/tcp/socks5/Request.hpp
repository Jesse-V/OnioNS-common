
#ifndef SOCKS5_REQUEST_HPP
#define SOCKS5_REQUEST_HPP

#include "Enums.hpp"
#include <string>
#include <boost/asio.hpp>

namespace Socks5
{
class Request
{
 public:
  Request();
  Request(Command cmd, AddressType atype, std::string address, uint16_t port);

  boost::asio::mutable_buffers_1 toBuffer();

 private:
  const uint8_t version_ = 0x05;
  Command command_;
  AddressType addressType_;
  std::string address_;
  uint16_t port_;

  unsigned char buffer_[255];
};
}

#endif
