
#include "Reply.hpp"

namespace Socks5
{
Reply::Reply(boost::asio::mutable_buffer mbuffer)
{
  from_buffer(mbuffer);
}

uint8_t Reply::version() const
{
  return version_;
}

ReplyCode Reply::reply() const
{
  return reply_;
}

AddressType Reply::atype() const
{
  return address_type_;
}

std::string Reply::address() const
{
  return address_;
}

uint16_t Reply::port() const
{
  return port_;
}

void Reply::from_buffer(boost::asio::mutable_buffer mbuffer)
{
  // size_t buffer_size = boost::asio::buffer_size(mbuffer);
  unsigned char* buffer = boost::asio::buffer_cast<unsigned char*>(mbuffer);

  reply_ = static_cast<ReplyCode>(buffer[1]);
  address_type_ = static_cast<AddressType>(buffer[3]);

  size_t address_size{};
  if (address_type_ == AddressType::domainname)
  {
    address_size = static_cast<uint8_t>(buffer[4]);
    address_ = std::string(buffer + 5, buffer + 5 + address_size);

    // adding 1 to size -- first byte of domain name address
    // is length of domain name
    ++address_size;
  }
  else
  {
    if (address_type_ == AddressType::ipv4)
    {
      address_size = 4;
    }
    else if (address_type_ == AddressType::ipv6)
    {
      address_size = 16;
    }
    address_ = std::string(buffer + 4, buffer + 4 + address_size);
  }

  port_ = static_cast<uint8_t>(buffer[4 + address_size]) << 8;
  port_ += static_cast<uint8_t>(buffer[4 + address_size + 1]);
}
}
