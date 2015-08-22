
#ifndef SOCKS5_REQUEST_HPP
#define SOCKS5_REQUEST_HPP

#include "Command.hpp"
#include "AddressType.hpp"
#include <string>
#include <boost/asio.hpp>

namespace Socks5
{
class Request
{
 public:
  Request() {}
  Request(Command cmd, AddressType atype, std::string address, uint16_t port);

  boost::asio::mutable_buffers_1 to_buffer();

 private:
  const uint8_t version_ = 0x05;
  Command command_;
  // const uint8_t reserved_ = 0x00;
  AddressType address_type_;
  std::string address_;
  uint16_t port_;

  unsigned char buffer_[255];
};
}

#endif
