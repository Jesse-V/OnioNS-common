
#include "Request.hpp"

namespace Socks5
{
Request::Request(Command cmd,
                 AddressType atype,
                 std::string address,
                 uint16_t port)
    : command_(cmd), address_type_(atype), address_(address), port_(port)
{
}

boost::asio::mutable_buffers_1 Request::to_buffer()
{
  // calculating buffer size
  size_t address_size{};
  if (address_type_ == AddressType::ipv4)
  {
    address_size = 4;
  }
  else if (address_type_ == AddressType::domainname)
  {
    address_size =
        address_.length() + 1;  // n bytes of address and 1 byte containing n
  }
  else if (address_type_ == AddressType::ipv6)
  {
    address_size = 16;
  }
  size_t buffer_size{6 + address_size};

  buffer_[0] = version_;
  buffer_[1] = static_cast<uint8_t>(command_);
  buffer_[2] = 0x00;  // reserved
  buffer_[3] = static_cast<uint8_t>(address_type_);

  size_t buf_pos = 4;
  if (address_type_ == AddressType::domainname)
  {
    buffer_[buf_pos] = address_.length();
    std::memcpy(buffer_ + 5, address_.data(), address_.length());
  }
  else
  {
    std::memcpy(buffer_ + buf_pos, address_.data(), address_size);
  }

  buf_pos += address_size;
  buffer_[buf_pos] = static_cast<uint8_t>((0xff00 & port_) >> 8);
  buffer_[buf_pos + 1] = static_cast<uint8_t>(0x00ff & port_);

  return boost::asio::buffer(buffer_, buffer_size);
}
}
