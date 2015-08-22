
#ifndef SOCKS5_ADDRESS_TYPE_HPP
#define SOCKS5_ADDRESS_TYPE_HPP

#include <cstdint>

namespace Socks5
{
enum class AddressType : uint8_t
{
  ipv4 = 0x01,
  domainname = 0x03,
  ipv6 = 0x04
};
}

#endif
