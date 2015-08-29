
#include "Request.hpp"

namespace Socks5
{
Request::Request()
{
  memset(buffer_, 0, 255);
}



Request::Request(Command cmd,
                 AddressType atype,
                 std::string address,
                 uint16_t port)
    : command_(cmd), addressType_(atype), address_(address), port_(port)
{
  memset(buffer_, 0, 255);
}



boost::asio::mutable_buffers_1 Request::toBuffer()
{
  // calculating buffer size
  size_t addressSize{};
  if (addressType_ == AddressType::IP_V4)
    addressSize = 4;
  else if (addressType_ == AddressType::DOMAIN_NAME)
    addressSize =
        address_.length() + 1;  // n bytes of address and 1 byte containing n
  else if (addressType_ == AddressType::IP_V6)
    addressSize = 16;

  buffer_[0] = version_;
  buffer_[1] = static_cast<uint8_t>(command_);
  buffer_[2] = 0x00;  // reserved
  buffer_[3] = static_cast<uint8_t>(addressType_);

  size_t bufferPos = 4;
  if (addressType_ == AddressType::DOMAIN_NAME)
  {
    buffer_[bufferPos] = address_.length();
    std::memcpy(buffer_ + 5, address_.data(), address_.length());
  }
  else
    std::memcpy(buffer_ + bufferPos, address_.data(), addressSize);

  bufferPos += addressSize;
  buffer_[bufferPos] = static_cast<uint8_t>((0xff00 & port_) >> 8);
  buffer_[bufferPos + 1] = static_cast<uint8_t>(0x00ff & port_);

  size_t buffer_size{6 + addressSize};
  return boost::asio::buffer(buffer_, buffer_size);
}
}
