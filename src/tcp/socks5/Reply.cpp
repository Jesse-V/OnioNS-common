
#include "Reply.hpp"

namespace Socks5
{
Reply::Reply(const boost::asio::mutable_buffer& mbuffer)
{
  // size_t buffer_size = boost::asio::buffer_size(mbuffer);
  unsigned char* buffer = boost::asio::buffer_cast<unsigned char*>(mbuffer);

  reply_ = static_cast<ReplyCode>(buffer[1]);
  addressType_ = static_cast<AddressType>(buffer[3]);

  size_t addressSize{};
  if (addressType_ == AddressType::DOMAIN_NAME)
  {
    addressSize = static_cast<uint8_t>(buffer[4]);
    address_ = std::string(buffer + 5, buffer + 5 + addressSize);

    // adding 1 to size -- first byte of domain name address
    // is length of domain name
    ++addressSize;
  }
  else
  {
    if (addressType_ == AddressType::IP_V4)
      addressSize = 4;
    else if (addressType_ == AddressType::IP_V6)
      addressSize = 16;

    address_ = std::string(buffer + 4, buffer + 4 + addressSize);
  }

  port_ = static_cast<uint8_t>(buffer[4 + addressSize]) << 8;
  port_ += static_cast<uint8_t>(buffer[4 + addressSize + 1]);
}



uint8_t Reply::getVersion() const
{
  return version_;
}



ReplyCode Reply::getReply() const
{
  return reply_;
}



AddressType Reply::getAddrType() const
{
  return addressType_;
}



std::string Reply::getAddress() const
{
  return address_;
}



uint16_t Reply::getPort() const
{
  return port_;
}
}
